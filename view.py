from flask import Flask, jsonify, request, send_file, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
from datetime import datetime, timedelta, date
from main import app, con
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
import unicodedata

app = Flask(__name__)
CORS(app, origins=["*"])

app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']

def generate_token(user_id, email):
    payload = {'id_usuario': user_id, 'email':email}
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def remover_bearer(token):
    if token.startswith('Bearer '):
        return token[len('Bearer '):]
    else:
        return token

def validar_senha(senha):
    if len(senha) < 8:
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres"}), 400

    if not re.search(r"[!@#$%¨&*(),.?\":<>{}|]", senha):
        return jsonify({"error": "A senha deve conter pelo menos um símbolo especial"}), 400

    if not re.search(r"[A-Z]", senha):
        return jsonify({"error": "A senha deve conter pelo menos uma letra maiúscula"}), 400

    if len(re.findall(r"\d", senha)) < 2:
        return jsonify({"error": "A senha deve conter pelo menos dois números"}), 400

    return True

def verificar_adm(id_cadastro):
    cur = con.cursor()
    cur.execute("SELECT tipo FROM cadastro WHERE id_cadastro = ?", (id_cadastro,))
    tipo = cur.fetchone()

    if tipo and tipo[0] == 'adm':
        return True
    else:
        return False

def normalizar_texto(texto):
    if texto is None:
        return ""
    texto = str(texto)
    return unicodedata.normalize('NFC', texto)

@app.route('/cadastro', methods=['POST'])
def cadastro_usuario():
    if not request.is_json:
        return jsonify({"error": "É necessário enviar JSON válido"}), 400

    data = request.get_json()

    if not data:
        return jsonify({"error": "JSON vazio"}), 400

    # Verifica autenticação (opcional para cadastro público de clientes)
    token = request.headers.get('Authorization')

    # Se tem token, valida quem está cadastrando
    if token:
        token = remover_bearer(token)
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            id_usuario_logado = payload.get('id_usuario')

            cur = con.cursor()
            cur.execute("SELECT tipo FROM CADASTRO WHERE ID_CADASTRO = ?", (id_usuario_logado,))
            result = cur.fetchone()
            tipo_usuario_logado = result[0].lower() if result else None
            cur.close()
        except:
            tipo_usuario_logado = None
    else:
        tipo_usuario_logado = None  # Cadastro público

    # Campos básicos obrigatórios
    campos_basicos = ['nome', 'email', 'telefone', 'senha']
    faltando = [campo for campo in campos_basicos if not data.get(campo)]
    if faltando:
        return jsonify({"error": f"Campos obrigatórios faltando: {', '.join(faltando)}"}), 400

    nome = data['nome']
    email = data['email']
    telefone = data['telefone']
    senha = data['senha']
    tipo = data.get('tipo', 'usuario').lower()
    categoria = data.get('categoria')

    # Regras de permissão para criar cada tipo de usuário
    if tipo == 'adm':
        # Apenas ADM pode criar outro ADM
        if tipo_usuario_logado != 'adm':
            return jsonify({"error": "Apenas administradores podem cadastrar outros administradores"}), 403

    elif tipo == 'profissional':
        # Apenas ADM pode criar profissional
        if tipo_usuario_logado != 'adm':
            return jsonify({"error": "Apenas administradores podem cadastrar profissionais"}), 403

        if not categoria:
            return jsonify({"error": "Campo 'categoria' é obrigatório para profissionais"}), 400

    elif tipo == 'usuario':
        # Qualquer um pode criar cliente (usuario):
        # - Cadastro público (sem token)
        # - ADM logado
        # - PROFISSIONAL logado
        # - Outro USUARIO logado (auto-cadastro)
        categoria = None  # Clientes não têm categoria

    else:
        return jsonify({"error": "Tipo inválido. Use: 'usuario', 'profissional' ou 'adm'"}), 400

    # Se for profissional ou adm, categoria não é necessária (exceto profissional)
    if tipo in ['adm', 'usuario']:
        categoria = None

    # Validar senha
    senha_check = validar_senha(senha)
    if senha_check is not True:
        return senha_check

    cur = con.cursor()

    # Verifica se o email já existe
    cur.execute("SELECT 1 FROM CADASTRO WHERE email = ?", (email,))
    if cur.fetchone():
        cur.close()
        return jsonify({"error": "Este email já está cadastrado!"}), 400

    senha_hashed = generate_password_hash(senha)

    # Insere o novo usuário
    cur.execute(
        "INSERT INTO CADASTRO (NOME, EMAIL, TELEFONE, SENHA, CATEGORIA, TIPO, ATIVO) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (nome, email, telefone, senha_hashed, categoria, tipo, True)
    )
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário cadastrado com sucesso!",
        'usuario': {
            'nome': nome,
            'email': email,
            'tipo': tipo,
            'categoria': categoria
        }
    }), 201

@app.route('/cadastro', methods=['GET'])
def listar_usuarios():
    try:
        # Pega o token do usuário logado
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token de autenticação necessário"}), 401

        token = remover_bearer(token)

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            id_usuario = payload.get('id_usuario')
        except:
            return jsonify({"error": "Token inválido"}), 401

        cur = con.cursor()

        # Busca o tipo do usuário logado
        cur.execute("SELECT tipo FROM CADASTRO WHERE ID_CADASTRO = ?", (id_usuario,))
        result = cur.fetchone()
        if not result:
            cur.close()
            return jsonify({"error": "Usuário não encontrado"}), 404

        tipo_usuario = result[0].lower()

        # Pega o filtro opcional por tipo (ex: ?tipo=profissional)
        tipo_filtro = request.args.get('tipo')

        if tipo_usuario == 'adm':
            # ADM vê TODOS os usuários (com filtro opcional por tipo)
            if tipo_filtro:
                cur.execute("""
                    SELECT id_cadastro, nome, email, telefone, tipo, categoria, ativo 
                    FROM CADASTRO 
                    WHERE tipo = ?
                    ORDER BY nome
                """, (tipo_filtro,))
            else:
                cur.execute("""
                    SELECT id_cadastro, nome, email, telefone, tipo, categoria, ativo 
                    FROM CADASTRO
                    ORDER BY nome
                """)

        elif tipo_usuario == 'profissional':
            # PROFISSIONAL vê apenas CLIENTES que fizeram agendamento COM ELE
            cur.execute("""
                SELECT DISTINCT 
                    C.ID_CADASTRO, 
                    C.NOME, 
                    C.EMAIL, 
                    C.TELEFONE, 
                    C.TIPO, 
                    C.CATEGORIA, 
                    C.ATIVO
                FROM CADASTRO C
                INNER JOIN AGENDA A ON A.ID_CLIENTE = C.ID_CADASTRO
                WHERE A.ID_CADASTRO = ?
                AND C.TIPO = 'usuario'
                ORDER BY C.NOME
            """, (id_usuario,))

        else:
            # Clientes não têm acesso a listar usuários
            cur.close()
            return jsonify({"error": "Acesso negado. Apenas administradores e profissionais podem listar usuários"}), 403

        rows = cur.fetchall()
        cur.close()

        if not rows:
            return jsonify({"message": "Nenhum usuário encontrado"}), 200

        usuarios = []
        for row in rows:
            usuarios.append({
                "id": row[0],
                "nome": row[1],
                "email": row[2],
                "telefone": row[3],
                "tipo": row[4],
                "categoria": row[5],
                "ativo": bool(row[6])
            })

        return jsonify(usuarios), 200

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/cadastro/<int:id>', methods=['PUT'])
def editar_usuario(id):
    cur = con.cursor()
    cur.execute("SELECT id_cadastro, nome, email, telefone, senha, categoria, tipo, ativo FROM CADASTRO WHERE id_cadastro = ?", (id,))
    usuarios_data = cur.fetchone()

    if not usuarios_data:
        cur.close()
        return jsonify({"error": "Usuário não foi encontrado"}), 404

    email_armazenado = usuarios_data[2]
    tipo_armazenado = usuarios_data[6]
    ativo_armazenado = usuarios_data[7]

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    telefone = data.get('telefone')
    senha = data.get('senha')
    categoria = data.get('categoria')
    tipo = data.get('tipo')
    ativo = data.get('ativo')

    # validação de senha
    if senha is not None:
        senha_check = validar_senha(senha)
        if senha_check is not True:
            return senha_check
        senha = generate_password_hash(senha)
    else:
        senha = usuarios_data[4]  # mantém a senha antiga

    if tipo is None:
        tipo = tipo_armazenado
    if ativo is None:
        ativo = ativo_armazenado

    if email_armazenado != email:
        cur.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
        if cur.fetchone():
            cur.close()
            return jsonify({"message": "Este usuário já foi cadastrado!"}), 400

    cur.execute(
        "UPDATE cadastro SET nome = ?, email = ?, telefone = ?, senha = ?, categoria = ?, tipo = ?, ativo = ? WHERE id_cadastro = ?",
        (nome, email, telefone, senha, categoria, tipo, ativo, id)
    )

    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário atualizado com sucesso!",
        'usuarios': {
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'categoria': categoria,
            'tipo': tipo,
            'ativo': ativo
        }
    })

tentativas = {}
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    print(email, senha)

    if not email or not senha:
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    cur = con.cursor()
    cur.execute("SELECT senha, tipo, id_cadastro, ativo, nome, telefone FROM CADASTRO WHERE email = ?", (email,))
    usuario = cur.fetchone()
    cur.close()

    if not usuario:
        return jsonify({"error": "Usuário ou senha inválidos"}), 401

    senha_armazenada, tipo, id_cadastro, ativo, nome, telefone = usuario

    if not ativo:
        return jsonify({"error": "Usuário inativo"}), 401

    if check_password_hash(senha_armazenada, senha):
        # Login OK, gera token
        token = generate_token(id_cadastro, email)
        return jsonify({
            "message": "Login realizado com sucesso!",
            "usuario": {
                "id_cadastro": id_cadastro,
                "nome": nome,
                "email": email,
                "telefone": telefone,
                "tipo": tipo,
                "token": token
            }
        })

    else:
        # Controle de tentativas
        if id_cadastro not in tentativas:
            tentativas[id_cadastro] = 0

        if tipo != 'adm':  # Se o usuário não for 'adm', contar as tentativas
            tentativas[id_cadastro] += 1
            if tentativas[id_cadastro] >= 3:
                cur = con.cursor()
                cur.execute("UPDATE CADASTRO SET ATIVO = false WHERE id_cadastro = ?", (id_cadastro,))
                con.commit()
                cur.close()
                return jsonify({"error": "Usuário inativado por excesso de tentativas."}), 403

        return jsonify({"error": "Senha incorreta"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"error": "Token de autenticação necessário"}), 401

    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        return jsonify({"message": "Logout realizado com sucesso!"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

codigos_temp = {}

@app.route('/servico', methods=['POST'])
def cadastrar_servico():
    try:
        # Pega o token do profissional logado
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token de autenticação necessário"}), 401

        token = remover_bearer(token)

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            id_profissional = payload.get('id_usuario')
        except:
            return jsonify({"error": "Token inválido"}), 401

        # Verifica se é profissional ou adm
        cur = con.cursor()
        cur.execute("SELECT tipo FROM CADASTRO WHERE ID_CADASTRO = ?", (id_profissional,))
        result = cur.fetchone()
        if not result:
            cur.close()
            return jsonify({"error": "Usuário não encontrado"}), 404

        tipo_usuario = result[0].lower()
        if tipo_usuario not in ['profissional', 'adm']:
            cur.close()
            return jsonify({"error": "Apenas profissionais e administradores podem cadastrar serviços"}), 403

        data = request.get_json()
        descricao = data.get('descricao')
        valor = data.get('valor')
        duracao_horas = data.get('duracao_horas')

        if not descricao or valor is None or duracao_horas is None:
            return jsonify({"error": "Todos os campos são obrigatórios"}), 400

        # Converter para minutos
        if isinstance(duracao_horas, str):
            try:
                horas, minutos = map(int, duracao_horas.split(":"))
                duracao_min = horas * 60 + minutos
            except ValueError:
                return jsonify({"error": "Formato inválido de duração (use HH:MM ou decimal)"}), 400
        else:
            duracao_min = int(float(duracao_horas) * 60)

        # Verifica se o serviço já existe para este profissional
        cur.execute("""
            SELECT COUNT(*) FROM SERVICO 
            WHERE DESCRICAO = ? AND ID_CADASTRO = ?
        """, (descricao, id_profissional))
        if cur.fetchone()[0] > 0:
            cur.close()
            return jsonify({"error": "Você já cadastrou um serviço com esta descrição"}), 400

        # Insere no banco com ID do profissional
        cur.execute("""
            INSERT INTO SERVICO (DESCRICAO, VALOR, DURACAO_HORAS, ID_CADASTRO)
            VALUES (?, ?, ?, ?)
        """, (descricao, valor, duracao_min, id_profissional))
        con.commit()
        cur.close()

        return jsonify({"message": "Serviço cadastrado com sucesso!"}), 201

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/servico', methods=['GET'])
def listar_servicos():
    try:
        # Pega o token (opcional para listar)
        token = request.headers.get('Authorization')
        id_profissional = request.args.get('id_profissional')  # Para filtrar por profissional

        cur = con.cursor()

        if id_profissional:
            # Lista serviços de um profissional específico
            cur.execute("""
                SELECT ID_SERVICO, DESCRICAO, VALOR, DURACAO_HORAS, ID_CADASTRO 
                FROM SERVICO 
                WHERE ID_CADASTRO = ?
            """, (id_profissional,))
        elif token:
            # Se tem token, pega o ID do usuário logado e lista apenas seus serviços
            token = remover_bearer(token)
            try:
                payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                id_usuario = payload.get('id_usuario')

                # Verifica tipo do usuário
                cur.execute("SELECT tipo FROM CADASTRO WHERE ID_CADASTRO = ?", (id_usuario,))
                result = cur.fetchone()
                tipo_usuario = result[0].lower() if result else None

                if tipo_usuario == 'adm':
                    # ADM vê todos os serviços
                    cur.execute("SELECT ID_SERVICO, DESCRICAO, VALOR, DURACAO_HORAS, ID_CADASTRO FROM SERVICO")
                elif tipo_usuario == 'profissional':
                    # Profissional vê apenas seus serviços
                    cur.execute("""
                        SELECT ID_SERVICO, DESCRICAO, VALOR, DURACAO_HORAS, ID_CADASTRO 
                        FROM SERVICO 
                        WHERE ID_CADASTRO = ?
                    """, (id_usuario,))
                else:
                    # Clientes veem todos os serviços disponíveis
                    cur.execute("SELECT ID_SERVICO, DESCRICAO, VALOR, DURACAO_HORAS, ID_CADASTRO FROM SERVICO")
            except:
                # Token inválido, lista todos
                cur.execute("SELECT ID_SERVICO, DESCRICAO, VALOR, DURACAO_HORAS, ID_CADASTRO FROM SERVICO")
        else:
            # Sem token, lista todos os serviços (para página pública)
            cur.execute("SELECT ID_SERVICO, DESCRICAO, VALOR, DURACAO_HORAS, ID_CADASTRO FROM SERVICO")

        servicos = cur.fetchall()
        cur.close()

        lista = []
        for s in servicos:
            duracao_min = s[3] if s[3] is not None else 0
            duracao_horas = round(duracao_min / 60, 2)

            lista.append({
                "id_servico": s[0],
                "descricao": s[1],
                "valor": float(s[2]) if s[2] is not None else 0.0,
                "duracao_horas": duracao_horas,
                "id_profissional": s[4]  # ID do profissional dono do serviço
            })

        return jsonify(lista), 200

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/servico/<int:id_servico>', methods=['PUT'])
def editar_servico(id_servico):
    try:
        # Pega o token do profissional logado
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token de autenticação necessário"}), 401

        token = remover_bearer(token)

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            id_usuario = payload.get('id_usuario')
        except:
            return jsonify({"error": "Token inválido"}), 401

        cur = con.cursor()

        # Verifica tipo do usuário
        cur.execute("SELECT tipo FROM CADASTRO WHERE ID_CADASTRO = ?", (id_usuario,))
        result = cur.fetchone()
        if not result:
            cur.close()
            return jsonify({"error": "Usuário não encontrado"}), 404

        tipo_usuario = result[0].lower()

        # Verifica se o serviço existe
        cur.execute("SELECT ID_CADASTRO FROM SERVICO WHERE ID_SERVICO = ?", (id_servico,))
        servico = cur.fetchone()
        if not servico:
            cur.close()
            return jsonify({"error": "Serviço não encontrado"}), 404

        id_profissional_dono = servico[0]

        # Verifica permissão
        if tipo_usuario == 'profissional' and id_profissional_dono != id_usuario:
            cur.close()
            return jsonify({"error": "Você só pode editar seus próprios serviços"}), 403

        # ADM pode editar qualquer serviço
        data = request.get_json()
        descricao = data.get('descricao')
        valor = data.get('valor')
        duracao = data.get('duracao_horas')

        if not descricao and valor is None and duracao is None:
            cur.close()
            return jsonify({"error": "Pelo menos um campo deve ser informado para atualizar"}), 400

        if descricao:
            cur.execute("UPDATE SERVICO SET DESCRICAO = ? WHERE ID_SERVICO = ?", (descricao, id_servico))
        if valor is not None:
            cur.execute("UPDATE SERVICO SET VALOR = ? WHERE ID_SERVICO = ?", (valor, id_servico))
        if duracao is not None:
            # Converte para minutos se necessário
            if isinstance(duracao, str):
                horas, minutos = map(int, duracao.split(":"))
                duracao_min = horas * 60 + minutos
            else:
                duracao_min = int(float(duracao) * 60)
            cur.execute("UPDATE SERVICO SET DURACAO_HORAS = ? WHERE ID_SERVICO = ?", (duracao_min, id_servico))

        con.commit()
        cur.close()

        return jsonify({"message": "Serviço atualizado com sucesso!"}), 200

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/servico/<int:id_servico>', methods=['DELETE'])
def deletar_servico(id_servico):
    try:
        # Pega o token do profissional logado
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token de autenticação necessário"}), 401

        token = remover_bearer(token)

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            id_usuario = payload.get('id_usuario')
        except:
            return jsonify({"error": "Token inválido"}), 401

        cur = con.cursor()

        # Verifica tipo do usuário
        cur.execute("SELECT tipo FROM CADASTRO WHERE ID_CADASTRO = ?", (id_usuario,))
        result = cur.fetchone()
        if not result:
            cur.close()
            return jsonify({"error": "Usuário não encontrado"}), 404

        tipo_usuario = result[0].lower()

        # Verifica se o serviço existe
        cur.execute("SELECT ID_CADASTRO FROM SERVICO WHERE ID_SERVICO = ?", (id_servico,))
        servico = cur.fetchone()
        if not servico:
            cur.close()
            return jsonify({"error": "Serviço não encontrado"}), 404

        id_profissional_dono = servico[0]

        # Verifica permissão
        if tipo_usuario == 'profissional' and id_profissional_dono != id_usuario:
            cur.close()
            return jsonify({"error": "Você só pode deletar seus próprios serviços"}), 403

        # ADM pode deletar qualquer serviço
        cur.execute("DELETE FROM SERVICO WHERE ID_SERVICO = ?", (id_servico,))
        con.commit()
        cur.close()

        return jsonify({"message": "Serviço deletado com sucesso!"}), 200

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        con.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/agenda', methods=['GET'])
def listar_agendamentos():
    try:
        cur = con.cursor()
        agora = datetime.now()

        # Pega o id_cadastro da query
        id_cadastro = request.args.get('id_cadastro')
        if not id_cadastro:
            return jsonify({"error": "ID do cadastro é obrigatório"}), 400

        # Busca o tipo do usuário no banco
        cur.execute("SELECT tipo FROM CADASTRO WHERE ID_CADASTRO = ?", (id_cadastro,))
        result = cur.fetchone()
        if not result:
            cur.close()
            return jsonify({"error": "Cadastro não encontrado"}), 404

        tipo_usuario = result[0]  # 'adm' ou 'profissional'

        # Monta a query dependendo do tipo
        if tipo_usuario.lower() == 'adm':
            # Administrador vê todos os agendamentos futuros
            cur.execute("""
                SELECT 
                    A.ID_AGENDA,
                    C.NOME AS PROFISSIONAL,
                    S.DESCRICAO AS SERVICO,
                    S.VALOR,
                    S.DURACAO_HORAS,
                    A.DATA_HORA
                FROM AGENDA A
                JOIN CADASTRO C ON A.ID_CADASTRO = C.ID_CADASTRO
                JOIN SERVICO S ON A.ID_SERVICO = S.ID_SERVICO
                WHERE A.DATA_HORA >= ?
                ORDER BY A.DATA_HORA ASC
            """, (agora,))
        else:
            # Profissional só vê seus próprios agendamentos futuros
            cur.execute("""
                SELECT 
                    A.ID_AGENDA,
                    C.NOME AS PROFISSIONAL,
                    S.DESCRICAO AS SERVICO,
                    S.VALOR,
                    S.DURACAO_HORAS,
                    A.DATA_HORA
                FROM AGENDA A
                JOIN CADASTRO C ON A.ID_CADASTRO = C.ID_CADASTRO
                JOIN SERVICO S ON A.ID_SERVICO = S.ID_SERVICO
                WHERE A.DATA_HORA >= ? AND A.ID_CADASTRO = ?
                ORDER BY A.DATA_HORA ASC
            """, (agora, id_cadastro))

        agendamentos = cur.fetchall()
        cur.close()

        lista = []
        for a in agendamentos:
            duracao_min = a[4] or 0
            horas = duracao_min // 60
            minutos = duracao_min % 60
            duracao_formatada = f"{horas:02}:{minutos:02}"

            lista.append({
                "id_agenda": a[0],
                "profissional": a[1],
                "servico": a[2],
                "valor": float(a[3]) if a[3] is not None else 0.0,
                "duracao": duracao_formatada,
                "data_hora": a[5].strftime("%Y-%m-%d %H:%M:%S")
            })

        return jsonify(lista), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/agenda', methods=['POST'])
def cadastrar_agendamento():
    try:
        data = request.get_json()
        id_cadastro = data.get('id_cadastro')
        id_servico = data.get('id_servico')
        data_hora_str = data.get('data_hora')  # ex: "21-10-2025" ou "21-10-2025 15:30:00"

        if not id_cadastro or not id_servico or not data_hora_str:
            return jsonify({"error": "Todos os campos são obrigatórios"}), 400

        # Converte a data
        try:
            data_hora = datetime.strptime(data_hora_str, "%d-%m-%Y %H:%M:%S")
        except ValueError:
            try:
                # Se não vier a hora, assume meio-dia
                data_hora = datetime.strptime(data_hora_str, "%d-%m-%Y")
                data_hora = data_hora.replace(hour=12, minute=0, second=0)
            except ValueError:
                return jsonify({"error": "Formato de data inválido. Use DD-MM-YYYY ou DD-MM-YYYY HH:MM:SS"}), 400

        # Bloqueia agendamento em horário passado
        if data_hora < datetime.now():
            return jsonify({"error": "Não é permitido criar agendamento em horário passado"}), 400

        cur = con.cursor()  # cria cursor normalmente
        try:
            # Busca duração do serviço (em minutos)
            cur.execute("SELECT DURACAO_HORAS FROM SERVICO WHERE ID_SERVICO = ?", (id_servico,))
            result = cur.fetchone()
            if not result or result[0] is None:
                return jsonify({"error": "Serviço não encontrado ou sem duração cadastrada"}), 400

            duracao_min = int(result[0])  # duração em minutos
            fim_novo_agendamento = data_hora + timedelta(minutes=duracao_min)

            # Busca agendamentos do mesmo profissional
            cur.execute("""
                SELECT A.DATA_HORA, S.DURACAO_HORAS
                FROM AGENDA A
                JOIN SERVICO S ON A.ID_SERVICO = S.ID_SERVICO
                WHERE A.ID_CADASTRO = ?
            """, (id_cadastro,))

            agendamentos = cur.fetchall()

            # Verifica conflitos
            for ag in agendamentos:
                inicio_existente = ag[0]
                duracao_existente = ag[1] if ag[1] is not None else 60
                fim_existente = inicio_existente + timedelta(minutes=int(duracao_existente))

                if (data_hora < fim_existente) and (fim_novo_agendamento > inicio_existente):
                    return jsonify({"error": "O horário conflita com outro agendamento do profissional"}), 400

            # Insere o novo agendamento
            cur.execute("""
                INSERT INTO AGENDA (ID_CADASTRO, ID_SERVICO, DATA_HORA)
                VALUES (?, ?, ?)
            """, (id_cadastro, id_servico, data_hora))
            con.commit()

        finally:
            cur.close()  # fecha o cursor corretamente

        return jsonify({"message": "Agendamento cadastrado com sucesso!"}), 201

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/agenda/<int:id_agenda>', methods=['DELETE'])
def cancelar_agendamento(id_agenda):
    try:
        cur = con.cursor()

        id_profissional = request.args.get('id_profissional')
        if not id_profissional:
            return jsonify({"error": "ID do profissional é obrigatório"}), 400

        # Verifica se o agendamento existe e pertence ao profissional
        cur.execute("SELECT ID_AGENDA, ID_CADASTRO FROM AGENDA WHERE ID_AGENDA = ?", (id_agenda,))
        agendamento = cur.fetchone()

        if not agendamento:
            cur.close()
            return jsonify({"error": "Agendamento não encontrado"}), 404

        if int(agendamento[1]) != int(id_profissional):
            cur.close()
            return jsonify({"error": "Você não pode cancelar agendamentos de outro profissional"}), 403

        # Deleta o agendamento
        cur.execute("DELETE FROM AGENDA WHERE ID_AGENDA = ?", (id_agenda,))
        con.commit()
        cur.close()

        return jsonify({"message": "Agendamento cancelado com sucesso"}), 200

    except Exception as e:
        con.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/painel-admin', methods=['GET', 'POST'])
def painel_admin():
    # Renderiza o HTML para GET sem parâmetros
    if request.method == 'GET' and not request.args.get('data_inicial'):
        return render_template('painel_administrativo.html')

    # Obtém as datas do GET ou POST JSON
    if request.method == 'GET':
        data_inicial = request.args.get('data_inicial')
        data_final = request.args.get('data_final')
    else:
        dados = request.get_json(silent=True) or {}
        data_inicial = dados.get('data_inicial')
        data_final = dados.get('data_final')

    # Define intervalo padrão para hoje caso datas não sejam informadas
    if not data_inicial or not data_final:
        hoje = date.today()
        data_inicial_dt = datetime.combine(hoje, datetime.min.time())
        data_final_dt = datetime.combine(hoje, datetime.max.time())
    else:
        data_inicial_dt = datetime.strptime(data_inicial, '%Y-%m-%d').replace(hour=0, minute=0, second=0)
        data_final_dt = datetime.strptime(data_final, '%Y-%m-%d').replace(hour=23, minute=59, second=59)

    data_inicial_str = data_inicial_dt.strftime('%Y-%m-%d %H:%M:%S')
    data_final_str = data_final_dt.strftime('%Y-%m-%d %H:%M:%S')

    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token de autenticação necessário"}), 401

        token = remover_bearer(token)

        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        id_usuario = payload.get('id_usuario')

        cur = con.cursor()

        # Obtém o tipo de usuário (adm, profissional, usuario)
        cur.execute("SELECT tipo FROM CADASTRO WHERE id_cadastro = ?", (id_usuario,))
        resultado = cur.fetchone()
        if not resultado:
            cur.close()
            return jsonify({"error": "Usuário não encontrado"}), 404

        tipo_usuario = resultado[0].lower()

        # Permite acesso somente para administradores e profissionais
        if tipo_usuario not in ['adm', 'profissional']:
            cur.close()
            return jsonify({"error": "Acesso negado. Apenas administradores e profissionais podem acessar o painel."}), 403

        if tipo_usuario == 'adm':
            # ADM: conta apenas RESERVAS FEITAS POR CLIENTES (ID_CLIENTE não nulo)
            cur.execute("""
                SELECT COUNT(*) FROM AGENDA
                WHERE DATA_HORA >= ? AND DATA_HORA <= ? 
                AND ID_CLIENTE IS NOT NULL
            """, (data_inicial_str, data_final_str))
            numero_clientes_agendou = cur.fetchone()[0] or 0

            # Quantidade de clientes ÚNICOS que fizeram reserva
            cur.execute("""
                SELECT COUNT(DISTINCT ID_CLIENTE) FROM AGENDA
                WHERE DATA_HORA >= ? AND DATA_HORA <= ?
                AND ID_CLIENTE IS NOT NULL
            """, (data_inicial_str, data_final_str))
            quantidade_clientes = cur.fetchone()[0] or 0

            # Faturamento de TODAS as reservas (com e sem ID_CLIENTE)
            cur.execute("""
                SELECT S.VALOR
                FROM AGENDA A
                INNER JOIN SERVICO S ON S.ID_SERVICO = A.ID_SERVICO
                WHERE A.DATA_HORA >= ? AND A.DATA_HORA <= ?
            """, (data_inicial_str, data_final_str))

            rows = cur.fetchall()
            faturamento_total = 0.0
            for row in rows:
                if row[0] is not None:
                    faturamento_total += float(row[0])

        else:
            # PROFISSIONAL: conta apenas reservas de clientes COM ELE
            cur.execute("""
                SELECT COUNT(*) FROM AGENDA
                WHERE DATA_HORA >= ? AND DATA_HORA <= ? 
                AND ID_CADASTRO = ?
                AND ID_CLIENTE IS NOT NULL
            """, (data_inicial_str, data_final_str, id_usuario))
            numero_clientes_agendou = cur.fetchone()[0] or 0

            # Clientes únicos que reservaram COM ELE
            cur.execute("""
                SELECT COUNT(DISTINCT ID_CLIENTE) FROM AGENDA
                WHERE DATA_HORA >= ? AND DATA_HORA <= ? 
                AND ID_CADASTRO = ?
                AND ID_CLIENTE IS NOT NULL
            """, (data_inicial_str, data_final_str, id_usuario))
            quantidade_clientes = cur.fetchone()[0] or 0

            # Faturamento apenas dos serviços DELE
            cur.execute("""
                SELECT S.VALOR
                FROM AGENDA A
                INNER JOIN SERVICO S ON S.ID_SERVICO = A.ID_SERVICO
                WHERE A.DATA_HORA >= ? AND A.DATA_HORA <= ? 
                AND A.ID_CADASTRO = ?
            """, (data_inicial_str, data_final_str, id_usuario))

            rows = cur.fetchall()
            faturamento_total = 0.0
            for row in rows:
                if row[0] is not None:
                    faturamento_total += float(row[0])

        cur.close()

        hoje = date.today()
        return jsonify({
            'mensagem': "Painel Administrativo",
            'periodo': {
                'data_inicial': data_inicial or hoje.strftime('%Y-%m-%d'),
                'data_final': data_final or hoje.strftime('%Y-%m-%d')
            },
            'numero_clientes_agendou': numero_clientes_agendou,
            'quantidade_clientes': quantidade_clientes,
            'faturamento_total': round(faturamento_total, 2)
        })

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401
    except Exception as e:
        import traceback
        return jsonify({
            'erro': str(e),
            'tipo': type(e).__name__,
            'detalhes': traceback.format_exc()
        }), 500

@app.route('/relatorio-faturamento', methods=['GET'])
def relatorio_faturamento():
    try:
        cur = con.cursor()

        data_inicial = request.args.get('data_inicial')
        data_final = request.args.get('data_final')

        if not data_inicial or not data_final:
            hoje = date.today()
            data_inicial = hoje.isoformat()
            data_final = hoje.isoformat()

        # Converte para datetime com hora completa
        data_inicial_dt = datetime.strptime(data_inicial, '%Y-%m-%d').replace(hour=0, minute=0, second=0)
        data_final_dt = datetime.strptime(data_final, '%Y-%m-%d').replace(hour=23, minute=59, second=59)

        # Formato para Firebird
        data_inicial_str = data_inicial_dt.strftime('%Y-%m-%d %H:%M:%S')
        data_final_str = data_final_dt.strftime('%Y-%m-%d %H:%M:%S')

        cur.execute(f"""
            SELECT 
                S.DESCRICAO, 
                COUNT(A.ID_AGENDA) AS qtd, 
                CAST(COALESCE(S.VALOR, 0) AS DOUBLE PRECISION) AS valor_unitario
            FROM AGENDA A
            JOIN SERVICO S ON S.ID_SERVICO = A.ID_SERVICO
            WHERE A.DATA_HORA >= '{data_inicial_str}' AND A.DATA_HORA <= '{data_final_str}'
            GROUP BY S.DESCRICAO, S.VALOR
            ORDER BY S.DESCRICAO
        """)

        resultados = cur.fetchall()
        cur.close()

        # Cria o PDF
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        largura, altura = A4

        # Cabeçalho
        pdf.setTitle("Relatório de Faturamento")
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(50, altura - 50, "Relatório de Faturamento")

        pdf.setFont("Helvetica", 11)
        pdf.drawString(50, altura - 75, f"Período: {data_inicial} até {data_final}")

        # Linha separadora
        pdf.line(50, altura - 85, largura - 50, altura - 85)

        # Cabeçalho da tabela
        y = altura - 110
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, "Serviço")
        pdf.drawString(250, y, "Qtd.")
        pdf.drawString(330, y, "Valor Unit.")
        pdf.drawString(450, y, "Total")

        # Linha após cabeçalho
        pdf.line(50, y - 5, largura - 50, y - 5)

        y -= 25
        total_geral = 0.0

        # Dados
        pdf.setFont("Helvetica", 11)

        if resultados and len(resultados) > 0:
            for servico, qtd, valor_unitario in resultados:
                # Converte valores
                qtd = int(qtd) if qtd else 0
                valor_unitario = float(valor_unitario) if valor_unitario else 0.0
                total_servico = qtd * valor_unitario
                total_geral += total_servico

                # Verifica se precisa de nova página
                if y < 100:
                    pdf.showPage()
                    pdf.setFont("Helvetica", 11)
                    y = altura - 50

                pdf.drawString(50, y, normalizar_texto(servico) if servico else "Sem descrição")
                pdf.drawString(260, y, str(qtd))
                pdf.drawString(330, y, f"R$ {valor_unitario:.2f}")
                pdf.drawString(450, y, f"R$ {total_servico:.2f}")
                y -= 20
        else:
            pdf.setFont("Helvetica-Oblique", 11)
            pdf.drawString(50, y, "Nenhum faturamento encontrado no período.")
            y -= 20

        # Linha antes do total
        y -= 10
        pdf.line(50, y, largura - 50, y)

        # Total geral
        y -= 25
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y, f"Total Faturamento: R$ {total_geral:.2f}")

        # Rodapé
        pdf.setFont("Helvetica", 8)
        pdf.drawString(50, 30, f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M')}")

        pdf.save()
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"relatorio_faturamento_{data_inicial}_a_{data_final}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        import traceback
        return jsonify({
            "error": str(e),
            "detalhes": traceback.format_exc()
        }), 500

@app.route('/relatorio-agendamentos', methods=['GET'])
def relatorio_agendamentos():
    try:
        cur = con.cursor()

        data_inicial = request.args.get('data_inicial')
        data_final = request.args.get('data_final')

        if not data_inicial or not data_final:
            hoje = date.today()
            data_inicial = hoje.isoformat()
            data_final = hoje.isoformat()

        # Converte para datetime com hora completa
        data_inicial_dt = datetime.strptime(data_inicial, '%Y-%m-%d').replace(hour=0, minute=0, second=0)
        data_final_dt = datetime.strptime(data_final, '%Y-%m-%d').replace(hour=23, minute=59, second=59)

        # Formato para Firebird
        data_inicial_str = data_inicial_dt.strftime('%Y-%m-%d %H:%M:%S')
        data_final_str = data_final_dt.strftime('%Y-%m-%d %H:%M:%S')

        # Consulta: Clientes que fizeram agendamentos (apenas onde ID_CLIENTE não é nulo)
        cur.execute("""
            SELECT C.NOME, COUNT(A.ID_AGENDA) AS total_agendamentos
            FROM AGENDA A
            INNER JOIN CADASTRO C ON C.ID_CADASTRO = A.ID_CLIENTE
            WHERE A.DATA_HORA >= ? AND A.DATA_HORA <= ?
            AND A.ID_CLIENTE IS NOT NULL
            GROUP BY C.NOME, C.ID_CADASTRO
            ORDER BY C.NOME
        """, (data_inicial_str, data_final_str))

        resultados = cur.fetchall()
        cur.close()

        # Cria o PDF
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        largura, altura = A4

        # Cabeçalho
        pdf.setTitle("Relatório de Clientes - Agendamentos")
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(50, altura - 50, "Relatório de Clientes - Agendamentos")

        pdf.setFont("Helvetica", 11)
        pdf.drawString(50, altura - 75, f"Período: {data_inicial} até {data_final}")

        # Linha separadora
        pdf.line(50, altura - 85, largura - 50, altura - 85)

        # Cabeçalho da tabela
        y = altura - 110
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, "Cliente")
        pdf.drawString(400, y, "Agendamentos")

        # Linha após cabeçalho
        pdf.line(50, y - 5, largura - 50, y - 5)

        y -= 25
        total_agendamentos = 0
        total_clientes = 0

        # Dados
        pdf.setFont("Helvetica", 11)

        if resultados and len(resultados) > 0:
            for nome_cliente, qtd in resultados:
                # Verifica se precisa de nova página
                if y < 100:
                    pdf.showPage()
                    pdf.setFont("Helvetica", 11)
                    y = altura - 50

                pdf.drawString(50, y, normalizar_texto(nome_cliente) if nome_cliente else "Cliente sem nome")
                pdf.drawString(430, y, str(qtd))
                total_agendamentos += qtd
                total_clientes += 1
                y -= 20
        else:
            pdf.setFont("Helvetica-Oblique", 11)
            pdf.drawString(50, y, "Nenhum cliente fez agendamento no período.")
            y -= 20

        # Linha antes do total
        y -= 10
        pdf.line(50, y, largura - 50, y)

        # Totais
        y -= 25
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, f"Total de Clientes: {total_clientes}")
        y -= 20
        pdf.drawString(50, y, f"Total de Agendamentos: {total_agendamentos}")

        # Rodapé
        pdf.setFont("Helvetica", 8)
        pdf.drawString(50, 30, f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M')}")

        pdf.save()
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"relatorio_clientes_agendamentos_{data_inicial}_a_{data_final}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        import traceback
        return jsonify({
            "error": str(e),
            "detalhes": traceback.format_exc()
        }), 500

@app.route('/relatorio-clientes', methods=['GET'])
def relatorio_clientes():
    try:
        cur = con.cursor()

        data_inicial = request.args.get('data_inicial')
        data_final = request.args.get('data_final')

        if not data_inicial or not data_final:
            hoje = date.today()
            data_inicial = hoje.isoformat()
            data_final = hoje.isoformat()

        # Converte para datetime com hora completa
        data_inicial_dt = datetime.strptime(data_inicial, '%Y-%m-%d').replace(hour=0, minute=0, second=0)
        data_final_dt = datetime.strptime(data_final, '%Y-%m-%d').replace(hour=23, minute=59, second=59)

        # Formato para Firebird
        data_inicial_str = data_inicial_dt.strftime('%Y-%m-%d %H:%M:%S')
        data_final_str = data_final_dt.strftime('%Y-%m-%d %H:%M:%S')

        # Consulta corrigida: pega CLIENTES (ID_CLIENTE) que fizeram reservas
        cur.execute("""
            SELECT DISTINCT C.NOME
            FROM AGENDA A
            INNER JOIN CADASTRO C ON C.ID_CADASTRO = A.ID_CLIENTE
            WHERE A.DATA_HORA >= ? AND A.DATA_HORA <= ?
            AND A.ID_CLIENTE IS NOT NULL
            ORDER BY C.NOME
        """, (data_inicial_str, data_final_str))

        clientes = cur.fetchall()
        cur.close()

        # Cria o PDF
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        largura, altura = A4

        # Cabeçalho
        pdf.setTitle("Relatório de Clientes")
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(50, altura - 50, "Relatório de Clientes")

        pdf.setFont("Helvetica", 11)
        pdf.drawString(50, altura - 75, f"Período: {data_inicial} até {data_final}")

        # Linha separadora
        pdf.line(50, altura - 85, largura - 50, altura - 85)

        # Cabeçalho da lista
        y = altura - 110
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, "Clientes que realizaram reservas:")

        # Linha após cabeçalho
        pdf.line(50, y - 5, largura - 50, y - 5)

        y -= 25
        total_clientes = len(clientes)

        # Lista de clientes
        pdf.setFont("Helvetica", 11)

        if clientes and len(clientes) > 0:
            for (nome,) in clientes:
                # Verifica se precisa de nova página
                if y < 100:
                    pdf.showPage()
                    pdf.setFont("Helvetica", 11)
                    y = altura - 50

                # Adiciona bullet point
                pdf.drawString(50, y, "•")
                pdf.drawString(65, y, normalizar_texto(nome) if nome else "Sem nome")
                y -= 20
        else:
            pdf.setFont("Helvetica-Oblique", 11)
            pdf.drawString(50, y, "Nenhum cliente realizou reserva no período.")
            y -= 20

        # Linha antes do total
        y -= 10
        pdf.line(50, y, largura - 50, y)

        # Total de clientes
        y -= 25
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, f"Total de Clientes: {total_clientes}")

        # Rodapé
        pdf.setFont("Helvetica", 8)
        pdf.drawString(50, 30, f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M')}")

        pdf.save()
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"relatorio_clientes_{data_inicial}_a_{data_final}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        import traceback
        return jsonify({
            "error": str(e),
            "detalhes": traceback.format_exc()
        }), 500

@app.route('/agenda/criar', methods=['POST'])
def criar_agendamento():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token de autenticação necessário"}), 401

        token = remover_bearer(token)

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            id_cliente = payload.get('id_usuario')  # Cliente logado
        except:
            return jsonify({"error": "Token inválido"}), 401

        data = request.get_json()
        id_profissional = data.get('id_profissional')
        id_servico = data.get('id_servico')
        data_hora_str = data.get('data_hora')

        if not all([id_profissional, id_servico, data_hora_str]):
            return jsonify({"error": "Todos os campos são obrigatórios"}), 400

        try:
            data_hora = datetime.strptime(data_hora_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return jsonify({"error": "Formato de data inválido. Use YYYY-MM-DD HH:MM:SS"}), 400

        if data_hora < datetime.now():
            return jsonify({"error": "Não é permitido agendar horário passado"}), 400

        cur = con.cursor()

        # Verifica duração do serviço
        cur.execute("SELECT DURACAO_HORAS FROM SERVICO WHERE ID_SERVICO = ?", (id_servico,))
        result = cur.fetchone()
        if not result or result[0] is None:
            return jsonify({"error": "Serviço não encontrado ou sem duração cadastrada"}), 400

        duracao_min = int(result[0])
        fim_agendamento = data_hora + timedelta(minutes=duracao_min)

        # Verifica conflito de horários do profissional
        cur.execute("""
            SELECT A.DATA_HORA, S.DURACAO_HORAS
            FROM AGENDA A
            JOIN SERVICO S ON A.ID_SERVICO = S.ID_SERVICO
            WHERE A.ID_CADASTRO = ?
        """, (id_profissional,))

        agendamentos = cur.fetchall()
        for ag in agendamentos:
            inicio_existente = ag[0]
            duracao_existente = ag[1] if ag[1] else 60
            fim_existente = inicio_existente + timedelta(minutes=duracao_existente)
            if (data_hora < fim_existente) and (fim_agendamento > inicio_existente):
                return jsonify({"error": "O horário conflita com outro agendamento do profissional"}), 400

        # Insere novo agendamento com ID_CLIENTE
        cur.execute("""
            INSERT INTO AGENDA (ID_CADASTRO, ID_SERVICO, DATA_HORA, ID_CLIENTE)
            VALUES (?, ?, ?, ?)
        """, (id_profissional, id_servico, data_hora, id_cliente))

        con.commit()
        cur.close()

        return jsonify({"message": "Agendamento criado com sucesso!"}), 201

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/agenda/meus-agendamentos', methods=['GET'])
def listar_meus_agendamentos():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token de autenticação necessário"}), 401

        token = remover_bearer(token)

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            id_cliente = payload.get('id_usuario')
        except:
            return jsonify({"error": "Token inválido"}), 401

        cur = con.cursor()
        cur.execute("""
            SELECT A.ID_AGENDA, A.DATA_HORA, S.NOME AS SERVICO, C.NOME AS PROFISSIONAL
            FROM AGENDA A
            JOIN SERVICO S ON A.ID_SERVICO = S.ID_SERVICO
            JOIN CADASTRO C ON A.ID_CADASTRO = C.ID_CADASTRO
            WHERE A.ID_CLIENTE = ?
            ORDER BY A.DATA_HORA ASC
        """, (id_cliente,))

        rows = cur.fetchall()
        cur.close()

        agendamentos = []
        for ag in rows:
            agendamentos.append({
                "id_agenda": ag[0],
                "data_hora": ag[1].strftime("%Y-%m-%d %H:%M:%S"),
                "servico": ag[2],
                "profissional": ag[3]
            })

        return jsonify(agendamentos), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/horarios-disponiveis', methods=['GET'])
def horarios_disponiveis():
    try:
        data = request.args.get('data')  # formato: "2025-09-02"
        id_profissional = request.args.get('id_profissional')
        id_servico = request.args.get('id_servico')

        if not data or not id_profissional or not id_servico:
            return jsonify({"error": "Parâmetros obrigatórios: data, id_profissional, id_servico"}), 400

        cur = con.cursor()

        # Busca duração do serviço
        cur.execute("SELECT DURACAO_HORAS FROM SERVICO WHERE ID_SERVICO = ?", (id_servico,))
        result = cur.fetchone()
        if not result:
            cur.close()
            return jsonify({"error": "Serviço não encontrado"}), 404

        duracao_min = int(result[0]) if result[0] else 60

        # Converte a data
        try:
            data_obj = datetime.strptime(data, "%Y-%m-%d")
        except ValueError:
            cur.close()
            return jsonify({"error": "Formato de data inválido. Use YYYY-MM-DD"}), 400

        # Gera horários possíveis (ex: das 8h às 18h, de hora em hora)
        horarios_possiveis = []
        for hora in range(8, 19):  # 8h até 18h
            for minuto in [0, 30]:  # a cada 30 minutos
                horario = data_obj.replace(hour=hora, minute=minuto, second=0)
                if horario > datetime.now():  # Só horários futuros
                    horarios_possiveis.append(horario)

        # Busca agendamentos existentes do profissional neste dia
        inicio_dia = data_obj.replace(hour=0, minute=0, second=0)
        fim_dia = data_obj.replace(hour=23, minute=59, second=59)

        cur.execute("""
            SELECT A.DATA_HORA, S.DURACAO_HORAS
            FROM AGENDA A
            JOIN SERVICO S ON A.ID_SERVICO = S.ID_SERVICO
            WHERE A.ID_CADASTRO = ? AND A.DATA_HORA BETWEEN ? AND ?
        """, (id_profissional, inicio_dia, fim_dia))

        agendamentos = cur.fetchall()
        cur.close()

        # Filtra horários disponíveis
        horarios_disponiveis = []
        for horario in horarios_possiveis:
            fim_novo = horario + timedelta(minutes=duracao_min)
            disponivel = True

            for ag in agendamentos:
                inicio_existente = ag[0]
                duracao_existente = ag[1] if ag[1] else 60
                fim_existente = inicio_existente + timedelta(minutes=int(duracao_existente))

                # Verifica conflito
                if (horario < fim_existente) and (fim_novo > inicio_existente):
                    disponivel = False
                    break

            if disponivel:
                horarios_disponiveis.append({
                    "data_hora": horario.strftime("%Y-%m-%d %H:%M:%S"),
                    "hora_formatada": horario.strftime("%H:%M")
                })

        return jsonify(horarios_disponiveis), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/profissionais-por-servico', methods=['GET'])
def profissionais_por_servico():
    try:
        id_servico = request.args.get('id_servico')

        if not id_servico:
            return jsonify({"error": "id_servico é obrigatório"}), 400

        cur = con.cursor()

        cur.execute("""
            SELECT C.ID_CADASTRO, C.NOME
            FROM CADASTRO C
            JOIN SERVICO S ON C.ID_CADASTRO = S.ID_CADASTRO
            WHERE S.ID_SERVICO = ?
        """, (id_servico,))

        profissionais = cur.fetchall()
        cur.close()

        lista = [
            {"id_profissional": p[0], "nome": p[1]}
            for p in profissionais
        ]

        return jsonify(lista), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

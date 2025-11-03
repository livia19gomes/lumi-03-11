from flask import Flask, jsonify, request, send_file
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

    # campos básicos obrigatórios (tipo NÃO está aqui)
    campos_basicos = ['nome', 'email', 'telefone', 'senha']
    faltando = [campo for campo in campos_basicos if not data.get(campo)]
    if faltando:
        return jsonify({"error": f"Campos obrigatórios faltando: {', '.join(faltando)}"}), 400

    nome = data['nome']
    email = data['email']
    telefone = data['telefone']
    senha = data['senha']
    tipo = data.get('tipo', 'usuario').lower()   # se não vier, assume "usuario"
    categoria = data.get('categoria')

    if tipo == 'profissional' and not categoria:
        return jsonify({"error": "Campo 'categoria' é obrigatório para profissionais"}), 400

    # se for adm ou usuario, categoria não é necessária
    if tipo in ['adm', 'usuario']:
        categoria = None

    senha_check = validar_senha(senha)
    if senha_check is not True:
        return senha_check

    cur = con.cursor()

    cur.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
    if cur.fetchone():
        cur.close()
        return jsonify({"error": "Este usuário já foi cadastrado!"}), 400

    senha_hashed = generate_password_hash(senha)

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
    }), 200

@app.route('/cadastro', methods=['GET'])
def listar_usuarios():
    try:
        cur = con.cursor()

        tipo = request.args.get('tipo')

        if tipo:
            cur.execute("""
                SELECT id_cadastro, nome, email, telefone, tipo, categoria, ativo 
                FROM CADASTRO 
                WHERE tipo = ?
            """, (tipo,))
        else:
            cur.execute("""
                SELECT id_cadastro, nome, email, telefone, tipo, categoria, ativo 
                FROM CADASTRO
            """)

        rows = cur.fetchall()
        cur.close()

        if not rows:
            return jsonify({"message": "Nenhum usuário encontrado"}), 404

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
        return jsonify({"error": str(e)}), 500

@app.route('/cadastro/<int:id>', methods=['DELETE'])
def deletar_Usuario(id):
    cur = con.cursor()

    cur.execute("SELECT 1 FROM cadastro WHERE id_cadastro = ?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({"error": "Usuario não encontrado"}), 404

    cur.execute("DELETE FROM cadastro WHERE id_cadastro = ?", (id,))
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuario excluído com sucesso!",
        'id_cadastro': id
    })

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
        data = request.get_json()
        descricao = data.get('descricao')
        valor = data.get('valor')
        duracao_horas = data.get('duracao_horas')  # ex.: "01:30" ou 1.5

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
            # Se veio decimal (1.5 horas)
            duracao_min = int(float(duracao_horas) * 60)

        cur = con.cursor()

        # Verifica se o serviço já existe
        cur.execute("SELECT COUNT(*) FROM SERVICO WHERE DESCRICAO = ?", (descricao,))
        if cur.fetchone()[0] > 0:
            return jsonify({"error": "Este serviço já está cadastrado"}), 400

        # Insere no banco (em minutos)
        cur.execute("""
            INSERT INTO SERVICO (DESCRICAO, VALOR, DURACAO_HORAS)
            VALUES (?, ?, ?)
        """, (descricao, valor, duracao_min))
        con.commit()
        cur.close()

        return jsonify({"message": "Serviço cadastrado com sucesso!"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/servico', methods=['GET'])
def listar_servicos():
    try:
        cur = con.cursor()
        cur.execute("SELECT ID_SERVICO, DESCRICAO, VALOR, DURACAO_HORAS FROM SERVICO")
        servicos = cur.fetchall()
        cur.close()

        lista = []
        for s in servicos:
            duracao_min = s[3] if s[3] is not None else 0
            # Converte minutos para horas decimais
            duracao_horas = round(duracao_min / 60, 2)  # ex.: 90 min → 1.5 horas

            lista.append({
                "id_servico": s[0],
                "descricao": s[1],
                "valor": float(s[2]) if s[2] is not None else 0.0,
                "duracao_horas": duracao_horas
            })

        return jsonify(lista), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/servico/<int:id_servico>', methods=['PUT'])
def editar_servico(id_servico):
    try:
        data = request.get_json()

        descricao = data.get('descricao')
        valor = data.get('valor')
        duracao = data.get('duracao_horas')

        if not descricao and valor is None and duracao is None:
            return jsonify({"error": "Pelo menos um campo deve ser informado para atualizar"}), 400

        cur = con.cursor()

        cur.execute("SELECT COUNT(*) FROM SERVICO WHERE ID_SERVICO = ?", (id_servico,))
        if cur.fetchone()[0] == 0:
            cur.close()
            return jsonify({"error": "Serviço não encontrado"}), 404

        if descricao:
            cur.execute("UPDATE SERVICO SET DESCRICAO = ? WHERE ID_SERVICO = ?", (descricao, id_servico))
        if valor is not None:
            cur.execute("UPDATE SERVICO SET VALOR = ? WHERE ID_SERVICO = ?", (valor, id_servico))
        if duracao is not None:
            cur.execute("UPDATE SERVICO SET DURACAO_HORAS = ? WHERE ID_SERVICO = ?", (duracao, id_servico))

        con.commit()
        cur.close()

        return jsonify({"message": "Serviço atualizado com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/horarios_disponiveis', methods=['GET'])
def listar_horarios():
    try:
        data = request.args.get('data')
        id_profissional = request.args.get('id_profissional')
        id_servico = request.args.get('id_servico')

        if not data or not id_profissional or not id_servico:
            return jsonify({"error": "Parâmetros obrigatórios: data, id_profissional, id_servico"}), 400

        cur = con.cursor()
        cur.execute("""
            SELECT HORARIO 
            FROM PR_HORARIOS_DISPONIVEIS(?, ?, ?)
        """, (data, id_profissional, id_servico))

        horarios = [row[0].strftime("%Y-%m-%d %H:%M:%S") for row in cur.fetchall()]

        return jsonify(horarios)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/agenda', methods=['GET'])
def listar_agendamentos():
    try:
        cur = con.cursor()

        agora = datetime.now()  # horário atual

        # Seleciona apenas agendamentos futuros e ordena do mais próximo para o mais distante
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

        # Verifica se o agendamento existe
        cur.execute("SELECT ID_AGENDA FROM AGENDA WHERE ID_AGENDA = ?", (id_agenda,))
        agendamento = cur.fetchone()

        if not agendamento:
            cur.close()
            return jsonify({"error": "Agendamento não encontrado"}), 404

        # Deleta o agendamento
        cur.execute("DELETE FROM AGENDA WHERE ID_AGENDA = ?", (id_agenda,))
        con.commit()
        cur.close()

        return jsonify({"message": "Agendamento cancelado com sucesso"}), 200

    except Exception as e:
        con.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/painel-admin', methods=['GET'])
def painel_admin():
    try:
        cur = con.cursor()

        # Pegando o período da query (opcional)
        data_inicial = request.args.get('data_inicial')
        data_final = request.args.get('data_final')

        if not data_inicial or not data_final:
            hoje = date.today().isoformat()
            data_inicial = hoje
            data_final = hoje

        # Número de agendamentos
        cur.execute("""
            SELECT COUNT(*)
            FROM AGENDA
            WHERE DATA_HORA BETWEEN ? AND ?
        """, (data_inicial, data_final))
        numero_agendamentos = cur.fetchone()[0] or 0

        # Faturamento total e por serviço
        cur.execute("""
            SELECT S.DESCRICAO, COUNT(A.ID_AGENDA) AS qtd, SUM(S.VALOR) AS total
            FROM AGENDA A
            JOIN SERVICO S ON A.ID_SERVICO = S.ID_SERVICO
            WHERE A.DATA_HORA BETWEEN ? AND ?
            GROUP BY S.DESCRICAO
        """, (data_inicial, data_final))
        resultados = cur.fetchall()

        faturamento_total = 0
        faturamento_por_servico = []
        for servico, qtd, total in resultados:
            faturamento_total += total or 0
            faturamento_por_servico.append({
                "servico": servico,
                "quantidade": qtd,
                "total": float(total or 0)
            })

        # Quantidade de clientes distintos
        cur.execute("""
            SELECT COUNT(DISTINCT ID_CADASTRO)
            FROM AGENDA
            WHERE DATA_HORA BETWEEN ? AND ?
        """, (data_inicial, data_final))
        quantidade_clientes = cur.fetchone()[0] or 0

        cur.close()

        return jsonify({
            "numero_agendamentos": numero_agendamentos,
            "faturamento_total": round(float(faturamento_total), 2),
            "faturamento_por_servico": faturamento_por_servico,
            "quantidade_clientes": quantidade_clientes,
            "mensagem": "Painel Administrativo"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/relatorio-agendamentos', methods=['GET'])
def relatorio_agendamentos():
    try:
        cur = con.cursor()

        data_inicial = request.args.get('data_inicial')
        data_final = request.args.get('data_final')
        if not data_inicial or not data_final:
            hoje = date.today().isoformat()
            data_inicial = hoje
            data_final = hoje

        cur.execute("""
            SELECT S.DESCRICAO, COUNT(A.ID_AGENDA)
            FROM AGENDA A
            JOIN SERVICO S ON S.ID_SERVICO = A.ID_SERVICO
            WHERE A.DATA_HORA BETWEEN ? AND ?
            GROUP BY S.DESCRICAO
        """, (data_inicial, data_final))

        resultados = cur.fetchall()
        cur.close()

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        largura, altura = A4

        pdf.setTitle("Relatório de Agendamentos")
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(200, 800, "Relatório de Agendamentos")
        pdf.setFont("Helvetica", 10)
        pdf.drawString(50, 780, f"Período: {data_inicial} até {data_final}")
        pdf.line(50, 775, 550, 775)

        y = 750
        total_agendamentos = 0

        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(50, y, "Serviço")
        pdf.drawString(400, y, "Qtd. Agendamentos")
        pdf.setFont("Helvetica", 10)
        y -= 20

        for servico, qtd in resultados:
            pdf.drawString(50, y, normalizar_texto(servico))
            pdf.drawString(430, y, str(qtd))
            total_agendamentos += qtd
            y -= 18
            if y < 100:
                pdf.showPage()
                y = 800
                pdf.setFont("Helvetica", 10)

        pdf.line(50, y-5, 550, y-5)
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(50, y-25, f"Total de Agendamentos: {total_agendamentos}")

        pdf.save()
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"relatorio_agendamentos_{data_inicial}_a_{data_final}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/relatorio-faturamento', methods=['GET'])
def relatorio_faturamento():
    try:
        cur = con.cursor()

        data_inicial = request.args.get('data_inicial')
        data_final = request.args.get('data_final')
        if not data_inicial or not data_final:
            hoje = date.today().isoformat()
            data_inicial = hoje
            data_final = hoje

        cur.execute("""
            SELECT S.DESCRICAO, COUNT(A.ID_AGENDA) AS qtd, S.VALOR AS valor_unitario
            FROM AGENDA A
            JOIN SERVICO S ON S.ID_SERVICO = A.ID_SERVICO
            WHERE A.DATA_HORA BETWEEN ? AND ?
            GROUP BY S.DESCRICAO, S.VALOR
        """, (data_inicial, data_final))

        resultados = cur.fetchall()
        cur.close()

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        largura, altura = A4

        pdf.setTitle("Relatório de Faturamento")
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(180, 800, "Relatório de Faturamento")
        pdf.setFont("Helvetica", 10)
        pdf.drawString(50, 780, f"Período: {data_inicial} até {data_final}")
        pdf.line(50, 775, 550, 775)

        y = 750
        total_geral = 0

        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(50, y, "Serviço")
        pdf.drawString(250, y, "Qtd.")
        pdf.drawString(330, y, "Valor Unitário")
        pdf.drawString(450, y, "Total")
        pdf.setFont("Helvetica", 10)
        y -= 20

        for servico, qtd, valor_unitario in resultados:
            total_servico = qtd * valor_unitario
            total_geral += total_servico
            pdf.drawString(50, y, normalizar_texto(servico))
            pdf.drawString(260, y, str(qtd))
            pdf.drawString(350, y, f"R$ {valor_unitario:.2f}")
            pdf.drawString(450, y, f"R$ {total_servico:.2f}")
            y -= 18
            if y < 100:
                pdf.showPage()
                y = 800
                pdf.setFont("Helvetica", 10)

        pdf.line(50, y-5, 550, y-5)
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(50, y-25, f"Total Faturamento: R$ {total_geral:.2f}")

        pdf.save()
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"relatorio_faturamento_{data_inicial}_a_{data_final}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/relatorio-clientes', methods=['GET'])
def relatorio_clientes():
    try:
        cur = con.cursor()

        data_inicial = request.args.get('data_inicial')
        data_final = request.args.get('data_final')
        if not data_inicial or not data_final:
            hoje = date.today().isoformat()
            data_inicial = hoje
            data_final = hoje

        cur.execute("""
            SELECT DISTINCT C.NOME
            FROM AGENDA A
            JOIN CADASTRO C ON C.ID_CADASTRO = A.ID_CADASTRO
            WHERE A.DATA_HORA BETWEEN ? AND ?
            ORDER BY C.NOME
        """, (data_inicial, data_final))

        clientes = cur.fetchall()
        cur.close()

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        largura, altura = A4

        pdf.setTitle("Relatório de Clientes")
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(180, 800, "Relatório de Clientes")
        pdf.setFont("Helvetica", 10)
        pdf.drawString(50, 780, f"Período: {data_inicial} até {data_final}")
        pdf.line(50, 775, 550, 775)

        y = 750
        total_clientes = len(clientes)

        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(50, y, "Clientes")
        pdf.setFont("Helvetica", 10)
        y -= 20

        for (nome,) in clientes:
            pdf.drawString(50, y, normalizar_texto(nome))
            y -= 18
            if y < 100:
                pdf.showPage()
                y = 800
                pdf.setFont("Helvetica", 10)

        pdf.line(50, y-5, 550, y-5)
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(50, y-25, f"Total de Clientes: {total_clientes}")

        pdf.save()
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"relatorio_clientes_{data_inicial}_a_{data_final}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


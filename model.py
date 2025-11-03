import fdb
class Cadastro:
    def __init__(self, id_cadastro, nome, email, telefone, senha, categoria, ativo):
        self.id_cadastro = id_cadastro
        self.nome = nome
        self.email = email
        self.telefone = telefone
        self.senha = senha
        self.categoria = categoria
        self.ativo = ativo

class Servicos:
    def __init__(self, id_servico, id_profissional, categoria, duracao, preco):
        self.id_servico = id_servico
        self.id_profissional = id_profissional
        self.categoria = categoria
        self.duracao = duracao
        self.preco = preco
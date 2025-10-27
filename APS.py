import pandas as pd

lista_itens = []

while True:
    print(" Digite 1 - Criar Itens \n Digite 2 - Deletar itens \n Digite 3 - Editar Itens \n Digite 4 - Salvar em arquivo Excel")
    numero = int(input("Digite um numero:"))
    if numero == 1:
        while True:
            item = input("Digite seu item ou digite sair: ")
            item = item.lower()
            if item != "sair":
                lista_itens.append(item)
                print(lista_itens)
            else:
                break

    elif numero == 2:
        item = input("Digite o item para remover ele da lista")
        item = item.lower()
        lista_itens.remove(item)
        print(lista_itens)
    elif numero == 3:
        item_para_alterar = input("Digite um item na lista para alterar")
        item = item.lower()
        item = input("Digite um novo item")
        for i, valor in enumerate(lista_itens):
            if valor == item_para_alterar:
                lista_itens[i] = item
        print(lista_itens)
    elif numero == 4:
        dados = pd.DataFrame(lista_itens)
        arquivo = dados.to_excel("Lista.xlsx")
    else:
        break

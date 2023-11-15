import random

adj_file = open("adj.txt", "r")
nouns_file = open("noun.txt", "r")

nouns = nouns_file.read().splitlines()
adj = adj_file.read().splitlines()     

username = (random.choice(adj).capitalize() + random.choice(nouns).capitalize())

print(username)

# A seguinte implementação de algoritmo criptográfico não deve ser usada em ambientes de produção,
# seu objetivo é puramente demonstrativo.

from typing import Literal
from sha256 import rotl, rotr
import copy

# Calcula a paridade dos bits 1 do número representado em binário de tamanho 1 byte
# Em resumo, essa função realiza o XOR com todos os bits na primeira "casa" binária,
# tal qual retorna 1 caso haja número ímpar de 1's e 0 caso contrário. Ao final, ela retorna apenas
# a primeira "casa" binária, que é o bit desejado.
def parity(n):
    for i in range(3):
        n ^= n >> (2**i)
    return n & 1

# Computa a operação de multiplicação de elementos do grupo finito GF(2^8).
# As operações de adição e multiplicação neste grupo são diferentes das convencionais, usadas comumente.
# O grupo define a operação de adição entre dois elementos a e b como o resultado da operação XOR entre a e b
# Já a multiplicação é um pouco mais complexa:
# representa-se os operandos em suas formas polinomiais (cada bit é o coeficiente de um polinomio de grau 7: x^7 + x^6 + x^3 + x + 1 é a representação de 11001011)
# multiplica-se os operandos convencionalmente, e, ao resultado, para cada coeficiente das potências de x, aplica-se a operação de módulo 2 (resto da divisão por 2),
# por fim, aplicando a operação de módulo (x^8 + x^4 + x^3 + x + 1) e obtendo o resultado. Para mais detalhes, consulte a especificação do padrão AES:
# https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf

def gf_ml(a, b):
    res = 0
    for _ in range(8):
        if a & 0x100:
           a ^= 0x11b
        if (b & 1):
            res ^= a
        b >>= 1
        a <<= 1
    return res

# Retorna o inverso multiplicativo de um elemento do grupo finito, a^-1, tal que
# a * (a^-1) = 1
# Caso a seja 0, retorna 0
def gf_inv(a):
    if a == 0x00:
        return 0x00
    for b in range(256):
        res = gf_ml(a, b)
        if res == 0x01:
            return b

# Calcula a S-Box
def ComputeSBox():
    v = 0b11110001
    sbox = list()
    for b in range(256):
        b_inv = gf_inv(b)
        s_rc = 0
        for i in range(8):
            bi = parity(v & b_inv)
            s_rc += bi * 2**i
            v = rotl(1,v,8)
        sbox.append(s_rc^0x63)
    return sbox

SBOX = ComputeSBox()
    

def SubBytes(state):
    for index, b in enumerate(state):
        state[index] = SBOX[b]

# A especificação do padrão AES define a operação shift como segue:
def shift(r) -> int:
    match r:
        case 1:
            return 1
        case 2:
            return 2
        case 3:
            return 3
        case _:
            raise

def ShiftRows(state):
    t_state = list()
    for i in range(16):
        r = i % 4
        c = i // 4
        if r != 0:
            t_state.append(state[r + 4*((c + shift(r))%4)])
        else:
            t_state.append(state[r + 4*c])
    state = t_state

def MixColumns(state):
    v = [2, 3, 1, 1]
    t_state = list()
    for i in range(4):
        w = state[4*i:4*(i+1)]
        for _ in range(4):
            b_s = 0
            for j, b in enumerate(w):
                b_s += b * v[j]
            b_s %= 2**8
            t_state.append(b_s)
            v = rotr(1,v,8)
    state = t_state

def AddRoundKey():
    pass

class AES:

    def __init__(self, key_length: Literal["128", "192", "256"] = "256"):
        self.key_length = key_length
        match key_length:
            case "128":
                self.Nk = 4
                self.Nr = 10
            case "192":
                self.Nk = 6
                self.Nr = 12
            case "256":
                self.Nk = 8
                self.Nr = 14

    def cipher(self, input, ):

        state = input

        AddRoundKey()

        for round in range(self.Nr):
            SubBytes()
            ShiftRows()
            MixColumns()
            AddRoundKey()
        
        SubBytes()
        ShiftRows()
        AddRoundKey()

        return state

        pass
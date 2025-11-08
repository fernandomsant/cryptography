# Esta implementação do algoritmo SHA-256 não tem por objetivo ser a mais eficiente; seu propósito é puramente demonstrativo.
# A especificação deste e de outros algoritmos pode ser encontrada em https://datatracker.ietf.org/doc/html/rfc6234

# As funções definidas abaixo são combinadas para realizar o hashing.
# Elas servem para fornecer imprevisibilidade ao resultado e minimizar colisões

def rotr(n, x, w = 32):
    return ((x>>n) | (x<<(w-n))) & 0xffffffff

def rotl(n, x, w = 32):
    return ((x<<n) | (x>>(w-n))) & 0xffffffff

def ch(x, y, z):
    return (x & y) ^ (~x & z) & 0xffffffff

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z) & 0xffffffff

def bsig0(x):
    return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x) & 0xffffffff

def bsig1(x):
    return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x) & 0xffffffff

def ssig0(x):
    return rotr(7, x) ^ rotr(18, x) ^ (x>>3) & 0xffffffff

def ssig1(x):
    return rotr(17, x) ^ rotr(19, x) ^ (x>>10) & 0xffffffff

# primeiros 32 bits das partes fracionárias das raízes quadradas dos 8 primeiros primos representadas em 64 bits
# H contém as 'hash values' iniciais
H = [0x6a09e667,
0xbb67ae85,
0x3c6ef372,
0xa54ff53a,
0x510e527f,
0x9b05688c,
0x1f83d9ab,
0x5be0cd19]

# primeiros 32 bits das partes fracionárias das raízes cúbicas dos 64 primeiros primos representadas em 64 bits
K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]

# As constantes declaradas acima adicionam "aleatoriedade" ao resultado. Ninguém as definiu, são constantes matemáticas.

class SHA256:

    def __init__(self, message: str):
        self.message = message


    def digest(self, encoding: str = 'utf-8') -> str:
        # Convertemos a mensagem a fim de processá-la.
        b_array = bytearray(self.message.encode(encoding))
        m_len = 8 * len(b_array)
        
        # A mensagem é processada para que, ao final, seu tamanho seja um múltiplo de 512 (bloco processável)
        # A regra de message padding diz:
        # Adiciona-se um bit '1' ao final da mensagem
        # Sendo L o tamanho da mensagem (em número de bits) e K o menor número inteiro positivo tal que
        # (L + 1 + K) ≡ 448 mod 512
        # Sendo 512, 448 e L são múltiplos de 8 (L é igual a 8 X numero_de_bytes), 1 + K é por consequência
        # também múltiplo de 8. Portanto, podemos adicionar o byte 0x80 (10000000 em binário) e ir adicionando
        # 0x00 (00000000 em binário), sem que nos "escape" o menor K, em vez de adicionar bit a bit e realizar a mesma verificação.
        b_array.append(0x80)
        while (8 * len(b_array)) % 512 != 448:
            b_array.append(0x00)
        
        # Adiciona-se ao final o tamanho da mensagem, que não deve ultrapassar 64 bits.
        b_array += bytearray(m_len.to_bytes(8, byteorder='big'))

        # Cada bloco processável possui 512 bits = 64 bytes
        # Deve-se iterar sobre os blocos, e por esse motivo, o loop abaixo divide o tamanho da messagem por 64
        for i in range(len(b_array)//64):
            # Cada bloco é dito ser composto por 16 words, cada uma composta por 4 bytes
            w = list()
            for t in range(16):
                # As 16 words de cada bloco são adicionadas à uma sequência (neste caso uma lista)
                wt = int.from_bytes(b_array[64*i+4*t:64*i+4*(t+1)], byteorder='big')
                w.append(wt)
            for t in range(16, 64):
                # A partir dessas 16 words, outras 48 são derivadas e adicionadas à sequência
                wt = (ssig1(w[t-2]) + w[t-7] + ssig0(w[t-15]) + w[t-16]) & 0xffffffff
                w.append(wt)
            # Aqui definimos os valores das working variables
            a = H[0]
            b = H[1]
            c = H[2]
            d = H[3]
            e = H[4]
            f = H[5]
            g = H[6]
            h = H[7]

            # Processando as words do bloco junto com as working variables e as constantes de K
            for t in range(64):
                t1 = (h + bsig1(e) + ch(e, f, g) + K[t] + w[t]) & 0xffffffff
                t2 = (bsig0(a) + maj(a, b, c)) & 0xffffffff
                h = g
                g = f
                f = e
                e = (d + t1) & 0xffffffff
                d = c
                c = b
                b = a
                a = (t1 + t2) & 0xffffffff

            # Os hash values são atualizados a cada bloco
            H[0] = (a + H[0]) & 0xffffffff
            H[1] = (b + H[1]) & 0xffffffff
            H[2] = (c + H[2]) & 0xffffffff
            H[3] = (d + H[3]) & 0xffffffff
            H[4] = (e + H[4]) & 0xffffffff
            H[5] = (f + H[5]) & 0xffffffff
            H[6] = (g + H[6]) & 0xffffffff
            H[7] = (h + H[7]) & 0xffffffff
        # Ao final, o resultado do hash é dado concatenando os hash values de 0 até 7
        return ''.join(f"{x:08x}" for x in H)
        

sha256 = SHA256('texto antes do hashing')
print(sha256.digest())
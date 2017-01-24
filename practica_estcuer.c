#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
//Practica Codigos y Criptografia curso 2016/2017.
//12.Diciembre.2016

//cipher(clave_entrada,IV_entrada,ruta_fichero)
int cipher(unsigned char *clave, unsigned char *IV, unsigned char *ruta_fichero) {
  //Abrimos fichero
  FILE *fileptr;
  fileptr = fopen(ruta_fichero, "rb");

  //Hallamos el tamanyo del fichero mediante un puntero al final del fichero
  unsigned long longitud_fichero;
  fseek(fileptr, 0, SEEK_END);
  longitud_fichero = ftell(fileptr);
  //Volvemos al principio del fichero para leerlo
  rewind(fileptr);

  //Leemos el fichero byte a byte al buffer mensaje
  //mensaje = m_0, m_1, m_2, ..., m_longitudfichero-1
  unsigned char *mensaje = malloc(longitud_fichero);

  for(int i = 0; i < longitud_fichero; i++) {
    fread(&mensaje[i], 1, 1, fileptr);
  }
  fclose(fileptr);

  //Comienza la expansion de clave. Almacenaremos solo las seis palabras actuales en cada ronda de cifrado
  unsigned int *W = malloc(6);

  //Primera ronda. A las 4 primeras palabras se les asigna la clave directamente. Representacion Big Endian.
  //                         tal que W0 = b0 + b1*256 + b2*256^2 + b3*256^3
  //                                 ...
  //                                 W3 = b12 + b13*256 + b14*256^2 + b15*256^3
  for(int w = 0; w<4; w++){
    W[w]=0;
    for(int i=w*4+(3); i>w*(4); i--){
      //1ra pasada: W[0] = 0x0000
      //2da pasada: W[0] = 0x00b30
      //3ra pasada: W[0] = 0x0b3b20
      W[w] = W[w]|clave[i];
      W[w] = W[w] << 8;
    }
    //W[0] = 0xb3b2b10
    W[w] = W[w]|clave[w*4];
    //W[0] = 0xb3b2b1b0
  }

  //A las 2 palabras restantes se les asigna el IV directamente
  //                            tal que W4 = IV0 + IV1*256 + IV2*256^2 + IV3*256^3
  //                                    W5 = IV4 + IV5*256 + IV6*256^2 + IV7*256^3
  for (int w=4;w<6;w++){
    W[w]=0;
    for(int i=(w-4)*4+(3); i>(w-4)*4; i--){
      W[w] = W[w]|IV[i];
      W[w] = W[w] << 8;
    }
    W[w] = W[w]|IV[w*4];
  }

 //El cifrado consistira en la siguiente secuencia W[n] = (W[n-1] << 13) + 11*W[n-3] + W[n-5] + W[n-6] + 2017
 unsigned int indice_modulado;
 for(int n = 6; n<21; n++){
   indice_modulado = n % 6; //Porque guardamos solo las 6 ultimas W
   W[indice_modulado] = (W[(n-1)%6] << 13) + 11 * W[(n-3)%6] + W[(n-5)%6] +  W[(n-6)%6] + 2017;
 }

 //Tras la ronda de cifrado numero 20, necesitaremos suficientes rondas como para obtener una secuencia cifrante tan larga como el mensaje
 //Cada palabra nos dara 4 bytes de la secuencia.
 unsigned long num_rondas = longitud_fichero/4 + (longitud_fichero%4!=0);
 unsigned char *secuencia_cifrante = malloc(num_rondas*4);

 for(int r = 21; r<num_rondas+21; r++){
   indice_modulado = r % 6; //Porque guardamos solo las 6 ultimas W
   W[indice_modulado] = (W[(r-1)%6] << 13) + 11 * W[(r-3)%6] + W[(r-5)%6] + W[(r-6)%6] + 2017;
   //Se obtendran 4 bytes de la palabra, guardandolos en el indice apropiado de secuencia_cifrante
   //Los bytes se extraen de la palabra mediante sucesivos shifts de 8 bits a la derecha.
   //El hecho de que secuencia_cifrante sea char se encarga de guardar solo los 8 bits correspondientes de la palabra.
   for (int h=0; h<4; h++){
     secuencia_cifrante[((r-21)*4)+h] = (W[indice_modulado] >> (8*h));
   }
  }

  //El mensaje cifrado se obtiene con la suma bit-wise de cada byte del mensaje y cada byte de la secuencia_cifrante
  unsigned char *cifrado = malloc(longitud_fichero);
  for (int i=0;i<longitud_fichero;i++){
    cifrado[i] = secuencia_cifrante[i] ^ mensaje[i];
  }

  //El fichero conteniendo el cifrado tendra el siguiente formato:
  //IV||zz||mensaje_cifrado
  unsigned int newlongitud_fichero = 8+2+longitud_fichero;
  unsigned char *new_file=malloc(newlongitud_fichero);

  for(int i=0; i<8; i++){
    new_file[i] = IV[i];
  }
  for(int i=8; i<10; i++){
    new_file[i] = 'z';
  }
  for(int i=10; i<newlongitud_fichero; i++){
    new_file[i] = cifrado[i-10];
  }

  //La ruta de fichero cifrado sera la ruta introducida con la extension de fichero .zz8
  char extension[4];
  strcpy(extension,".zz8");

  char ruta_fichero_nuevo[strlen(ruta_fichero)+strlen(extension)];
  strcpy(ruta_fichero_nuevo,ruta_fichero);
  strcat(ruta_fichero_nuevo,extension);

  FILE *foo =fopen(ruta_fichero_nuevo,"wb");
  fwrite(new_file, newlongitud_fichero, 1, foo);
  fclose(foo);

  return 0;
}

//decipher(clave_entrada,ruta_fichero)
int decipher(unsigned char *clave, unsigned char *ruta_fichero) {
  unsigned char *IV = malloc(8);
  //Abrimos fichero
  FILE *fileptr;
  fileptr = fopen(ruta_fichero, "rb");

  //Hallamos el tamanyo del fichero mediante un puntero al final del fichero. Tener en cuenta este tamanyo incluira el formato y el IV
  unsigned long longitud_fichero_formato;
  fseek(fileptr, 0, SEEK_END);
  longitud_fichero_formato = ftell(fileptr);
  //Volvemos al principio del fichero para leerlo
  rewind(fileptr);

  //Leemos los primeros 8 bytes para conseguir el IV
  for(int i = 0; i < 8; i++){
    fread(&IV[i],1,1,fileptr);
  }

  //Comprobamos que el formato es correcto (los siguientes dos caracteres son 'z')
  for(int i=0; i < 2; i++){
    char format;
    fread(&format,1,1,fileptr);
    if(format != 'z'){
      printf("Formato no valido.");
      exit(-1);
    }
  }

  long longitud_fichero = longitud_fichero_formato - 10;
  //Leemos el resto del fichero byte a byte al buffer cifrado
  //cifrado = c_0, c_1, c_2, ..., c_longitudfichero-1
  unsigned char *cifrado = malloc(longitud_fichero);

  for(int i = 0; i < longitud_fichero; i++) {
    fread(&cifrado[i], 1, 1, fileptr);
  }
  fclose(fileptr);

  //Comienza la expansion de clave. Almacenaremos solo las seis palabras actuales en cada ronda de cifrado
  unsigned int *W = malloc(6);

  //Primera ronda. A las 4 primeras palabras se les asigna la clave directamente. Representacion Big Endian.
  //                         tal que W0 = b0 + b1*256 + b2*256^2 + b3*256^3
  //                                 ...
  //                                 W3 = b12 + b13*256 + b14*256^2 + b15*256^3
  for(int w = 0; w<4; w++){
    W[w]=0;
    for(int i=w*4+(3); i>w*(4); i--){
      //1ra pasada: W[0] = 0x0000
      //2da pasada: W[0] = 0x00b30
      //3ra pasada: W[0] = 0x0b3b20
      W[w] = W[w]|clave[i];
      W[w] = W[w] << 8;
    }
    //W[0] = 0xb3b2b10
    W[w] = W[w]|clave[w*4];
    //W[0] = 0xb3b2b1b0
  }

  //A las 2 palabras restantes se les asigna el IV directamente
  //                            tal que W4 = IV0 + IV1*256 + IV2*256^2 + IV3*256^3
  //                                    W5 = IV4 + IV5*256 + IV6*256^2 + IV7*256^3
  for (int w=4;w<6;w++){
    W[w]=0;
    for(int i=(w-4)*4+(3); i>(w-4)*4; i--){
      W[w] = W[w]|IV[i];
      W[w] = W[w] << 8;
    }
    W[w] = W[w]|IV[w*4];
  }

 //El cifrado consistira en la siguiente secuencia W[n] = (W[n-1] << 13) + 11*W[n-3] + W[n-5] + W[n-6] + 2017
 unsigned int indice_modulado;
 for(int n = 6; n<21; n++){
   indice_modulado = n % 6; //Porque guardamos solo las 6 ultimas W
   W[indice_modulado] = (W[(n-1)%6] << 13) + 11 * W[(n-3)%6] + W[(n-5)%6] +  W[(n-6)%6] + 2017;
 }

 //Tras la ronda de cifrado numero 20, necesitaremos suficientes rondas como para obtener una secuencia cifrante tan larga como el mensaje
 //Cada palabra nos dara 4 bytes de la secuencia.
 unsigned long num_rondas = longitud_fichero/4 + (longitud_fichero%4!=0);
 unsigned char *secuencia_cifrante = malloc(num_rondas*4);

 for(int r = 21; r<num_rondas+21; r++){
   indice_modulado = r % 6; //Porque guardamos solo las 6 ultimas W
   W[indice_modulado] = (W[(r-1)%6] << 13) + 11 * W[(r-3)%6] + W[(r-5)%6] + W[(r-6)%6] + 2017;
   //printf("W%d = %x\n",r+20,W[indice_modulado]);
   //Se obtendran 4 bytes de la palabra, guardandolos en el indice apropiado de secuencia_cifrante
   //Los bytes se extraen de la palabra mediante sucesivos shifts de 8 bits a la derecha.
   //El hecho de que secuencia_cifrante sea char se encarga de guardar solo los 8 bits correspondientes de la palabra.
   for (int h=0; h<4; h++){
     secuencia_cifrante[((r-21)*4)+h] = (W[indice_modulado] >> (8*h));
   }
  }

  //El mensaje se obtiene con la suma bit-wise de cada byte del cifrado y cada byte de la secuencia_cifrante
  unsigned char *mensaje = malloc(longitud_fichero);
  for (int i=0;i<longitud_fichero;i++){
    mensaje[i] = secuencia_cifrante[i] ^ cifrado[i];
  }

  //La ruta de fichero cifrado sera la ruta introducida con la extension de fichero .dcf
  char extension[4];
  strcpy(extension,".dcf");

  char ruta_fichero_nuevo[strlen(ruta_fichero)+strlen(extension)];
  strcpy(ruta_fichero_nuevo,ruta_fichero);
  strcat(ruta_fichero_nuevo,extension);

  FILE *foo =fopen(ruta_fichero_nuevo,"wb");
  fwrite(mensaje, longitud_fichero, 1, foo);
  fclose(foo);

  return 0;
}

int main(int argc, char const *argv[]) {
  unsigned char *ruta_fichero = malloc(260);
  unsigned char *clave = malloc(16);
  unsigned char *IV = malloc(8);
  for(int i = 0; i<16; i++){
      clave[i] = 0;
  }
  for(int i=0; i<8; i++){
     IV[i] = 0;
  }
  int numero_opcion;
  int tim;
  printf("Elija la opcion: \n1 Cifrado.\n2 Descifrado.\n0 Salir\n");
  scanf("%d",&numero_opcion);
  switch (numero_opcion) {
    case 0:
      printf("Adios.\n");
      return 0;
      break;
    case 1:
      printf("CIFRADO:\nIntroduzca ruta del fichero a cifrar:\n");
      scanf("%s",ruta_fichero);
      printf("Introduzca clave de cifrado (maximo 16 bytes):\n");
      scanf("%s",clave);
      tim = time(NULL);
      for(int i=0; i<8; i++){
        IV[i] = tim >> (8*i);
      }
      cipher(clave,IV,ruta_fichero);
      printf("Fichero cifrado: %s.zz8\n",ruta_fichero);
      break;
    case 2:
      printf("DESCIFRADO:\nIntroduzca ruta del fichero a descifrar:\n");
      scanf("%s",ruta_fichero);
      printf("Introduzca clave de cifrado (maximo 16 bytes):\n");
      scanf("%s",clave);
      decipher(clave,ruta_fichero);
      printf("Fichero descifrado: %s.dcf\n",ruta_fichero);
      break;
    default:
      printf("Opcion incorrecta.\n");
      break;
  }
  return 0;
}

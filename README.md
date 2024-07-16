# Demo TSIG
Esta es la demo para tsig, es un proxy que retransmite los mensajes a el server, corre con dos pc's en la ip 192.168.100.(2|3)/24
- cliente es el 100.2, con los puertos 8887 y 8890
- server es el 100.3

comando para correr tsig con dig, ejecutar el main y en otra terminal ejecutar

```bash
dig -p8887 @127.0.0.1 ns1.nictest -k wena.key
```


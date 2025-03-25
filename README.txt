Il send funziona solo da veth1 quindi bisogna iniettare il programma eBPF su veth1_

sudo ip netns exec ns1 ./l4_lb -1 veth1_

Il send.py è composto da alcune funzioni modalità: 
-> send.py -i veth1 -maxp <numero massimo di pacchetti> -f <numero di flow>
Mandera per ogni flow un numero random di pacchetti tra 0 a maxp distribuiti in modo 
uniforme. Genera un grafico 
-> send.py -i veth1 -p <numero pacchetti> -f <numero di flow>
Genererà un numero di flow pari a n e per ogni flow manderà un numero di pacchetti 
uguali. 

Il receive non l'ho usato. Era solo per testare se riuscisse a leggere i pacchetti 
inviati con XDP_TX.

Non si vedono i pacchetti ocn XDP_TX. Per vederli usare XDP_PASS e usare wireshark sull'interfaccia 
veth1_ 

sudo ip netns exec ns1 wireshark 
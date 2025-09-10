Link-ul proiectului: https://github.com/AlexDorinIrimia/FlowGuard

Pentru a compila și crea executabilul, în Windows:
1. Se descarcă fișierele proiectului
2. Într-un terminal deschis în directorul ce conține proiectul, se rulează comanda: pyinstaller flowguard.spec

Pentru ca aplicația să funcționeze, este posibil să fie nevoie de descărcarea Microsoft Visual C++ Redistributable și Python împreună cu scipy. 

Pentru a rula executabilul, în Windows:
1. Se merge în directorul dist
2. Se intră în directorul flowguard
3. Se face click pe executabil sau, din terminal, se folosește comanda .\flowguard.exe
4. În browser, se scrie in bara de cautare: <ip-ul computerului>:5000

Pentru a compila și rula aplicația în alte sisteme de operare:
1. Se descarcă proiectul
2. Se rulează comanda: python run_ids.py
3. În browser, se scrie in bara de cautare: <ip-ul computerului>:5000 

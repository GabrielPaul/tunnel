# tunnel
rebuild tunnel from https://github.com/i183/tunnel

# Compile
enter code directory run  
`make`  
or  
`mkdir build && cd build && cmake ../. && make`  

# Usage
run tunneld at 192.168.16.193,run tunnel at 192.168.16.125  
after tunnel connected tunneld,tunnel will get a port number(33626)  
then send data to 192.168.16.192:33626,tunneld will transfer the data to 192.168.16.125:80(80 port can be specified by configure file)  
![img](https://github.com/GabrielPaul/tunnel/blob/main/doc/tunneld.gif)

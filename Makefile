null:
	@chmod 755 ./rawhttpget
	@sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
	@sudo ethtool --offload  enp0s3  rx off  tx off
	@sudo ethtool -K enp0s3 rx off
	@sudo ethtool -K enp0s3 tx off
	@sudo ethtool -K enp0s3 sg off
	@sudo ethtool -K enp0s3 tso off
	@sudo ethtool -K enp0s3 ufo off
	@sudo ethtool -K enp0s3 gso off
	@sudo ethtool -K enp0s3 gro off
	@sudo ethtool -K enp0s3 lro off 


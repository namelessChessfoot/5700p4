device := enp0s3
null:
	@chmod 755 ./rawhttpget
	@sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
	@sudo ethtool --offload  $(device)  rx off  tx off
	@sudo ethtool -K $(device) rx off
	@sudo ethtool -K $(device) tx off
	@sudo ethtool -K $(device) sg off
	@sudo ethtool -K $(device) tso off
	@sudo ethtool -K $(device) gso off
	@sudo ethtool -K $(device) gro off


<h1>DPS</h1>

<h1>Overview</h1>
<hr />
<p>DPS, Discovery Protocol Sniffer, is designed to easily gather and parse LLDP or CDP packets allowing the user to focus on other tasks.</p>
<p>Information parsed by DPS includes, but is not limited to, MAC addresses, IP addresses, Device Names/IDs, Device capabilities, and VLAN(s).</p>
<p>It was written in Python 3.10.12 and has been tested on Linux</p>

<h1>Dependencies</h1>
<hr />
<ul>
<li>Python 3</li>
<li>Scapy</li>
</ul>

<h1>To Execute</h1>
<hr />
<p>Simply run the python file. The tool will walk the user through specifying the details of their capture.</p>

<h1>Future Work</h1>
<hr />
<ul>
<li>Combine LLDP and CDP sniffing so the user does not have to specify which type of packet they would like to sniff.</li>
<li>Create a dictionary of discovered devices so the user is not duplicate results.</li>
</ul>

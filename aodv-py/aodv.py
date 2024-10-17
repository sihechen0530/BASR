# Imports
from threading import Timer, RLock, Thread

import select, time
from scapy.all import *

from packet import RREQ, RREP, RERR, DATA
import logging

# Defines
HELLO_INTERVAL = 1
DATA_INTERVAL = 2
HELLO_TIMEOUT = 2
PATH_DISCOVERY_TIME = 4
ACTIVE_ROUTE_TIMEOUT = 3
ALLOWED_HELLO_LOSS = 2
QUEUE_SIZE = 50
DATA_SIZE = 1350
NODES = ['10.0.56.{}'.format(i) for i in range(1, 10)]


# Class Definition
class aodv():

    # Constructor
    def __init__(self, ip):
        self.IP = ip
        self.seq_no = 0
        self.rreq_id = 0
        self.aodv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.aodv_sock.bind(("", 654))
        self.aodv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.data_sock.bind(("", 20000))
        self.data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.neighbors = dict()
        self.routing_table = dict()
        self.message_box = dict()
        self.rreq_id_list = dict()
        self.data_q = dict()
        self.status = 'Active'

    def runsrc(self):
        # Setup logging
        FORMAT = "%(asctime)s - {IP} - %(message)s "
        logging.basicConfig(level=logging.WARNING,
                            filename='/home/log_aodv_baseline.txt',
                            filemode='w',
                            format=FORMAT.format(IP=self.IP))
        logging.debug(" started on ip " + self.IP + " with pid " + str(os.getpid()))
        #hello_thread = Thread(target=self.aodv_send_hello)
        data_thread = Thread(target=self.data_send_a)
        aodv_sock_thread = Thread(target=self.aodv)
        data_sock_thread = Thread(target=self.data)
        aodv_sock_thread.start()
        data_sock_thread.start()
        #hello_thread.start()
        data_thread.start()

        # Thread start routine

    def runmal(self):
        # Setup logging
        FORMAT = "%(asctime)s - {IP} - %(message)s "
        logging.basicConfig(level=logging.WARNING,
                            filename='/home/log_aodv_baseline.txt',
                            filemode='w',
                            format=FORMAT.format(IP=self.IP))
        logging.debug(" started on ip " + self.IP + " with pid " + str(os.getpid()))
        #hello_thread = Thread(target=self.aodv_send_hello)
        data_thread = Thread(target=self.data_send_a)
        aodv_sock_thread = Thread(target=self.aodv_mal)
        data_sock_thread = Thread(target=self.data_mal)
        aodv_sock_thread.start()
        data_sock_thread.start()
        #hello_thread.start()
        data_thread.start()

    def aodv(self):
        while True:
            message, addr = self.aodv_sock.recvfrom(2048)
            logging.warning("Receiving route packet size: {}".format(len(message)))
            if message[0] == 1:
                packet = RREQ(message)
                self.aodv_process_rreq_packet(addr[0], packet)
            elif message[0] == 2:
                packet = RREP(message)
                self.aodv_process_rrep_packet(addr[0], packet)
                self.aodv_show_routing_table()
            elif message[0] == 3:
                packet = RERR(message)
                self.aodv_process_rerr_packet(addr[0], packet)
            else:
                logging.debug(message)

    def aodv_mal(self):
        while True:
            message, addr = self.aodv_sock.recvfrom(2048)
            logging.warning("Receiving route packet size: {}".format(len(message)))
            if message[0] == 1:
                packet = RREQ(message)
                self.aodv_process_rreq_packet_mal(addr[0], packet)
            elif message[0] == 2:
                packet = RREP(message)
                self.aodv_process_rrep_packet(addr[0], packet)
                self.aodv_show_routing_table()
            elif message[0] == 3:
                packet = RERR(message)
                self.aodv_process_rerr_packet(addr[0], packet)
            else:
                logging.debug(message)

    def data(self):
        while True:
            message, addr = self.data_sock.recvfrom(2048)
            logging.warning("Receiving data packet size: {}".format(len(message)))
            packet = DATA(message)
            self.data_process_packet(addr[0], packet)

    def data_mal(self):
        while True:
            message, addr = self.data_sock.recvfrom(2048)
            logging.warning("Receiving data packet size: {}".format(len(message)))
            packet = DATA(message)
            self.data_process_packet_mal(addr[0], packet)

    # Create / Restart the lifetime timer for the given route
    def aodv_restart_route_timer(self, dest_ip, create):
        if create == False:
            self.routing_table[dest_ip]['Lifetime'].cancel()

        timer = Timer(ACTIVE_ROUTE_TIMEOUT,
                      self.aodv_process_route_timeout, [dest_ip])
        self.routing_table[dest_ip]['Lifetime'] = timer
        self.routing_table[dest_ip]['Status'] = 'Active'
        timer.start()

    # Send a message
    def aodv_send_packet(self, dest_ip, packet):
        try:
            message_bytes = raw(packet)
            self.aodv_sock.sendto(message_bytes, (dest_ip, 654))
        except Exception as e:
            logging.debug(e)

    def data_send_packet(self, dest_ip, packet):
        try:
            if packet.OrigIP != self.IP:
                logging.warning("Forwarding data to {} from {} via {}".format(packet.DstIP, packet.OrigIP, dest_ip))
            else:
                logging.warning("Sending data to: {}".format(dest_ip))
            message_bytes = raw(packet)
            self.data_sock.sendto(message_bytes, (dest_ip, 20000))
        except Exception as e:
            logging.debug(e)

    # Send the hello message to all the nodes
    def aodv_send_hello(self):
        while True:
            # Send message to each node
            for node_ip in NODES:
                if node_ip != self.IP:
                    logging.warning("Sending aodv hello to: {}".format(node_ip))
                    packet = RREP()
                    packet.HopCount = 0
                    packet.DstIP = node_ip
                    packet.DstSeq = self.seq_no
                    packet.OrigIP = self.IP
                    packet.Lifetime = ALLOWED_HELLO_LOSS * HELLO_INTERVAL
                    self.aodv_send_packet(node_ip, packet)
            time.sleep(HELLO_INTERVAL)

    def data_send_a(self):
        logging.debug("sending hello message")
        while True:
            for node_ip in NODES:
                if node_ip != self.IP:
                    self.data_send_message(node_ip, 'a' * DATA_SIZE)
                    time.sleep(DATA_INTERVAL)
            time.sleep(DATA_INTERVAL)

    def aodv_send_rreq(self, dest_ip, dest_seq_no):
        logging.warning("Sending aodv rreq to: {}".format(dest_ip))
        # Increment the RREQ_ID
        self.rreq_id = self.rreq_id + 1
        # Increment our sequence number
        self.seq_no = self.seq_no + 1
        # Construct the RREQ packet
        packet = RREQ()
        packet.HopCount = 1
        packet.RREQID = self.rreq_id
        packet.DstIP = dest_ip
        packet.DstSeq = dest_seq_no
        packet.OrigIP = self.IP
        packet.OrigSeq = self.seq_no

        # Broadcast the RREQ packet to all the nodes
        for node in NODES:
            self.aodv_send_packet(node, packet)
        # Buffer the RREQ_ID for PATH_DISCOVERY_TIME. This is used to discard duplicate RREQ messages
        if self.IP in self.rreq_id_list:
            per_node_list = self.rreq_id_list[self.IP]
        else:
            per_node_list = dict()
        path_discovery_timer = Timer(PATH_DISCOVERY_TIME,
                                     self.aodv_process_path_discovery_timeout,
                                     [self.IP, self.rreq_id])
        per_node_list[self.rreq_id] = {'Timer-Callback': path_discovery_timer}
        self.rreq_id_list[self.IP] = {'RREQ_ID_List': per_node_list}
        path_discovery_timer.start()

    # Rebroadcast an RREQ request (Called when RREQ is received by an intermediate node)
    def aodv_forward_rreq(self, packet):
        packet.HopCount += 1
        for node in NODES:
            self.aodv_send_packet(node, packet)
            logging.debug("Forwarding aodv rreq from {} to {} via {}".format(packet.OrigIP, packet.DstIP, node))

    # Process an incoming RREQ message
    def aodv_process_rreq_packet(self, sender_ip, packet):
        # Extract the relevant parameters from the message
        hop_count = packet.HopCount
        rreq_id = packet.RREQID
        dest_ip = packet.DstIP
        dest_seq_no = packet.DstSeq
        orig_ip = packet.OrigIP
        orig_seq_no = packet.OrigSeq

        # Ignore the message if we are not active
        if self.status == "Inactive" or orig_ip == self.IP:
            return

        logging.warning("Received aodv rreq to {} from {} via {}".format(dest_ip, orig_ip, sender_ip))

        # Discard this RREQ if we have already received this before
        if orig_ip in self.rreq_id_list:
            node_list = self.rreq_id_list[orig_ip]
            per_node_rreq_id_list = node_list['RREQ_ID_List']
            if rreq_id in per_node_rreq_id_list:
                return

        # This is a new RREQ message. Buffer it first
        if orig_ip in self.rreq_id_list:
            per_node_list = self.rreq_id_list[orig_ip]
        else:
            per_node_list = dict()
        path_discovery_timer = Timer(PATH_DISCOVERY_TIME,
                                     self.aodv_process_path_discovery_timeout,
                                     [orig_ip, rreq_id])
        per_node_list[rreq_id] = {'Timer-Callback': path_discovery_timer}
        self.rreq_id_list[orig_ip] = {'RREQ_ID_List': per_node_list}
        path_discovery_timer.start()

        #
        # Check if we have a route to the source. If we have, see if we need
        # to update it. Specifically, update it only if:
        #
        # 1. The destination sequence number for the route is less than the
        #    originator sequence number in the packet
        # 2. The sequence numbers are equal, but the hop_count in the packet
        #    + 1 is lesser than the one in routing table
        # 3. The sequence number in the routing table is unknown
        #
        # If we don't have a route for the originator, add an entry
        self.aodv_update_routing_table(orig_ip, sender_ip, orig_seq_no, hop_count)

        #
        # Check if we are the destination. If we are, generate and send an
        # RREP back.
        #
        if self.IP == dest_ip:
            self.seq_no += 1
            self.aodv_send_rrep(orig_ip, dest_ip, sender_ip, self.seq_no, 0)
            return

        #
        # We are not the destination. Check if we have a valid route
        # to the destination. If we have, generate and send back an
        # RREP.
        #
        if dest_seq_no != 0 and dest_ip in self.routing_table:
            # Verify that the route is valid and has a higher seq number
            route = self.routing_table[dest_ip]
            route_dest_seq_no = route['Seq-No']
            if route_dest_seq_no > dest_seq_no:
                self.aodv_send_rrep(orig_ip, dest_ip, sender_ip, route_dest_seq_no, route['Hop-Count'])
        else:
            # Rebroadcast the RREQ
            self.aodv_forward_rreq(packet)

    # Process an incoming RREQ message
    def aodv_process_rreq_packet_mal(self, sender_ip, packet):
        # Extract the relevant parameters from the message
        hop_count = packet.HopCount
        rreq_id = packet.RREQID
        dest_ip = packet.DstIP
        dest_seq_no = packet.DstSeq
        orig_ip = packet.OrigIP
        orig_seq_no = packet.OrigSeq

        # Ignore the message if we are not active
        if self.status == "Inactive" or orig_ip == self.IP:
            return

        logging.warning("Received aodv rreq to {} from {} via {}".format(dest_ip, orig_ip, sender_ip))

        # Discard this RREQ if we have already received this before
        if orig_ip in self.rreq_id_list:
            node_list = self.rreq_id_list[orig_ip]
            per_node_rreq_id_list = node_list['RREQ_ID_List']
            if rreq_id in per_node_rreq_id_list:
                return

        # This is a new RREQ message. Buffer it first
        if orig_ip in self.rreq_id_list:
            per_node_list = self.rreq_id_list[orig_ip]
        else:
            per_node_list = dict()
        path_discovery_timer = Timer(PATH_DISCOVERY_TIME,
                                     self.aodv_process_path_discovery_timeout,
                                     [orig_ip, rreq_id])
        per_node_list[rreq_id] = {'Timer-Callback': path_discovery_timer}
        self.rreq_id_list[orig_ip] = {'RREQ_ID_List': per_node_list}
        path_discovery_timer.start()

        self.seq_no += 1
        self.aodv_send_rrep(orig_ip, dest_ip, sender_ip, 9999, 0)
        return


    # Send an RREP message back to the RREQ originator
    def aodv_send_rrep(self, orig_ip, dest_ip, next_hop, dest_seq_no, hop_count):
        logging.warning("Sending aodv rrep for orig:{} dest:{} via {}".format(orig_ip, dest_ip, next_hop))

        # Construct the RREP message
        packet = RREP()
        packet.HopCount = hop_count + 1
        packet.DstIP = dest_ip
        packet.DstSeq = dest_seq_no
        packet.OrigIP = orig_ip
        packet.Lifetime = ACTIVE_ROUTE_TIMEOUT

        # Now send the RREP to the RREQ originator along the next-hop
        self.aodv_send_packet(next_hop, packet)
        logging.debug(
            "[Sending RREP for " + dest_ip + " to " + orig_ip + " via " + next_hop + "']")

    # Forward an RREP message (Called when RREP is received by an intermediate node)
    def aodv_forward_rrep(self, next_hop, packet):
        packet.HopCount += 1
        self.aodv_send_packet(next_hop, packet)
        logging.warning("Forwarding aodv rrep for orig:{} dest:{} via {}".format(packet.OrigIP, packet.DstIP, next_hop))

    # Process an incoming RREP message
    def aodv_process_rrep_packet(self, sender_ip, packet):
        # Extract the relevant fields from the message
        hop_count = packet.HopCount
        dest_ip = packet.DstIP
        dest_seq_no = packet.DstSeq
        orig_ip = packet.OrigIP
        lifetime = packet.Lifetime

        if hop_count == 0:
            # Received Hello Broadcast from neighbor
            logging.warning("Received aodv hello from " + sender_ip)
            self.aodv_add_neighbor(sender_ip, dest_seq_no)
            return

        logging.warning("Received aodv rrep for orig:{} dest:{} via {}".format(orig_ip, dest_ip, sender_ip))

        self.aodv_update_routing_table(dest_ip, sender_ip, dest_seq_no, hop_count)
        if self.IP != orig_ip:
            # Now lookup the next-hop for the source and forward it
            if orig_ip in self.routing_table:
                route = self.routing_table[orig_ip]
                next_hop = route['Next-Hop']
                self.aodv_forward_rrep(next_hop, packet)
        # Check if we have any pending messages to this destination
        if dest_ip in self.data_q:
            for p in self.data_q[dest_ip]:
                self.data_send_packet(sender_ip, p)
                self.data_q[dest_ip].remove(p)

    # Generate and send a Route Error message
    def aodv_send_rerr(self, dest_ip, dest_seq_no):
        logging.warning("Sending rerr to: {}".format(dest_ip))
        # Construct the RERR message
        packet = RERR()
        packet.DestCount = 1
        packet.IP = dest_ip
        packet.Seq = dest_seq_no + 1
        # Now broadcast the RERR message
        for node in NODES:
            self.aodv_send_packet(node, packet)
            logging.debug("Sending RERR for " + dest_ip + " to " + node)

    # Forward a Route Error message
    def aodv_forward_rerr(self, packet):
        for node in NODES:
            self.aodv_send_packet(node, packet)
            logging.warning("Forwarding aodv rerr for {} to {}".format(packet.IP, node))

    # Process an incoming RERR message
    def aodv_process_rerr_packet(self, sender_ip, packet):
        # Extract the relevant fields from the message
        dest_ip = packet.IP
        dest_seq_no = packet.Seq
        if self.IP == dest_ip:
            return

        logging.warning("Received aodv rerr for {} from {}".format(dest_ip, sender_ip))

        #
        # Take action only if we have an active route to the destination with
        # sender as the next-hop
        #
        if dest_ip in self.routing_table:
            route = self.routing_table[dest_ip]
            if route['Status'] == 'Active' and route['Next-Hop'] == sender_ip and dest_seq_no > route['Seq-No']:
                # Mark the destination as inactive
                route['Status'] = "Inactive"

                # Forward the RERR to all the neighbors
                self.aodv_forward_rerr(packet)

    # Broadcast an RREQ message for the given destination

    def aodv_add_neighbor(self, neighbor, dest_seq_no):
        if neighbor != self.IP:
            if neighbor in self.neighbors:
                self.neighbors[neighbor]['Timer-Callback'].cancel()
            timer = Timer(HELLO_TIMEOUT,
                          self.aodv_process_neighbor_timeout, [neighbor])
            self.neighbors[neighbor] = {'Timer-Callback': timer}
            timer.start()

            logging.debug("Neighbors added successfully: ", self.neighbors)

            hop_count = 1
            status = 'Active'
            self.aodv_update_routing_table(neighbor, neighbor, dest_seq_no, hop_count)
            # Check if we have any pending messages to this destination
            if neighbor in self.data_q:
                for p in self.data_q[neighbor]:
                    self.data_send_packet(neighbor, p)
                    self.data_q[neighbor].remove(p)

    # Handle neighbor timeouts
    def aodv_process_neighbor_timeout(self, neighbor):
        # Update the routing table. Mark the route as inactive.
        if neighbor not in self.routing_table:
            return
        route = self.routing_table[neighbor]
        route['Status'] = 'Inactive'

        # Log a message
        logging.debug("aodv_process_neighbor_timeout: {} went down".format(neighbor))

        # Send an RERR to all the neighbors
        self.aodv_send_rerr(neighbor, route['Seq-No'])
        self.neighbors.pop(neighbor)
        # Try to repair the route
        dest_seq_no = route['Seq-No'] + 1
        self.aodv_send_rreq(neighbor, dest_seq_no)

    # Handle route timeouts
    def aodv_process_route_timeout(self, dest_ip):
        # Remove the route from the routing table
        if dest_ip in self.routing_table:
            route = self.routing_table[dest_ip]
            route['Lifetime'].cancel()
            self.routing_table.pop(dest_ip)
        logging.debug("aodv_process_route_timeout: removing " + dest_ip + " from the routing table.")

    # Handle Path Discovery timeouts
    def aodv_process_path_discovery_timeout(self, orig, rreq_id):
        # Remove the buffered RREQ_ID for the given node
        if orig in self.rreq_id_list:
            node_list = self.rreq_id_list[orig]
            per_node_rreq_id_list = node_list['RREQ_ID_List']
            if rreq_id in per_node_rreq_id_list:
                per_node_rreq_id_list.pop(rreq_id)

    # Send a message to a peer
    def data_send_message(self, dest_ip, message):
        # Format the packet
        packet = DATA()
        packet.OrigIP = self.IP
        packet.DstIP = dest_ip
        packet.Data = message
        # First check if we have a route for the destination
        if dest_ip in self.routing_table:
            # Route already present. Get the next-hop for the destination.
            destination = self.routing_table[dest_ip]

            if destination['Status'] == 'Inactive':
                # We don't have a valid route. Broadcast an RREQ.
                self.aodv_send_rreq(dest_ip, destination['Seq-No'])
                if dest_ip in self.data_q:
                    self.data_q[dest_ip].append(packet)
                else:
                    self.data_q[dest_ip] = [packet]
            else:
                next_hop = destination['Next-Hop']
                self.data_send_packet(next_hop, packet)
        else:
            # Initiate a route discovery message to the destination
            self.aodv_send_rreq(dest_ip, 0)
            # Buffer the packet and resend it once RREP is received
            if dest_ip in self.data_q:
                self.data_q[dest_ip].append(packet)
            else:
                self.data_q[dest_ip] = [packet]

    def data_process_packet(self, sender_ip, packet):
        # Extract the relevant parameters from the message
        hop_count = packet.HopCount + 1
        dest_ip = packet.DstIP
        orig_ip = packet.OrigIP

        # This is the destination
        if self.IP == dest_ip:
            logging.debug("Received data from {}".format(orig_ip))
            self.data_print_packet(packet)
            return

        if hop_count == 1:
            packet.Hop1 = self.IP
        elif hop_count == 2:
            packet.Hop2 = self.IP
        elif hop_count == 3:
            packet.Hop3 = self.IP
        elif hop_count == 4:
            packet.Hop4 = self.IP
        elif hop_count == 5:
            packet.Hop5 = self.IP
        elif hop_count == 6:
            packet.Hop6 = self.IP
        elif hop_count == 7:
            packet.Hop7 = self.IP
        elif hop_count == 8:
            packet.Hop8 = self.IP
        else:
            logging.debug(hop_count)
        packet.HopCount = hop_count
        if dest_ip in self.routing_table:
            route = self.routing_table[dest_ip]
            next_hop = route['Next-Hop']
            self.data_send_packet(next_hop, packet)
        else:
            if dest_ip in self.data_q:
                self.data_q[dest_ip].append(packet)
            else:
                self.data_q[dest_ip] = [packet]


    def data_process_packet_mal(self, sender_ip, packet):
        # Extract the relevant parameters from the message
        hop_count = packet.HopCount + 1
        dest_ip = packet.DstIP
        orig_ip = packet.OrigIP

        # This is the destination
        if self.IP == dest_ip:
            logging.debug("Received data from {}".format(orig_ip))
            self.data_print_packet(packet)
        return
        

    def aodv_update_routing_table(self, dest_ip, next_hop, dest_seq_no, hop_count):
        if dest_ip in self.routing_table:
            # TODO update lifetime timer for this route
            route = self.routing_table[dest_ip]
            if route['Seq-No'] < dest_seq_no:
                route['Seq-No'] = dest_seq_no
                self.aodv_restart_route_timer(dest_ip, False)
            elif route['Seq-No'] == dest_seq_no:
                if route['Hop-Count'] > hop_count:
                    route['Hop-Count'] = hop_count
                    route['Next-Hop'] = next_hop
                    self.aodv_restart_route_timer(dest_ip, False)

        elif dest_ip != self.IP:
            # TODO update lifetime timer for this route
            self.routing_table[dest_ip] = {'Next-Hop': next_hop,
                                           'Seq-No': dest_seq_no,
                                           'Hop-Count': hop_count,
                                           'Status': 'Active'}
            self.aodv_restart_route_timer(dest_ip, True)


    # Display the routing table for the current node
    def aodv_show_routing_table(self):
        logging.warning("Routing table: {}".format(self.routing_table))
        self.status = "Success"
        logging.warning("Neighbors: {}".format(self.neighbors))

    def data_print_packet(self, packet):
        logging.warning(
            "Received data {MSG} from {OrigIP} via hops: {HopList}".format(MSG=packet.Data[0:10], OrigIP=packet.OrigIP,
                                                                           HopList=[packet.Hop1, packet.Hop2,
                                                                                    packet.Hop3, packet.Hop4,
                                                                                    packet.Hop5, packet.Hop6,
                                                                                    packet.Hop7, packet.Hop8]))

# End of File

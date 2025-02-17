#include <iostream>
#include <string>
#include <algorithm>
#include <memory>
#include <cctype>
#include <ctime>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <stdint.h>
#include "ProtocolType.h"
#include <sys/time.h>
#include <Packet.h>
#include <PcapFilter.h>
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"


bool isValidNumber(const std::string& str, int minVal, int maxVal) {
    if (str.empty()) return false;
    for (char c : str) {
        if (!isdigit(c)) return false;
    }
    int num = std::stoi(str);
    return num >= minVal && num <= maxVal;
}


bool isValidIPAddress(std::string ip) {
    std::stringstream ss(ip);
    std::string segment;
    std::vector<std::string> octets;

    while (getline(ss, segment, '.')) {
        octets.push_back(segment);
    }

    if (octets.size() != 4) return false;

    for (const std::string& octet : octets) {
        if (!isValidNumber(octet, 0, 255)) return false;
    }
    return true;
}

// ******* The statistic struct ******* //
struct PacketStats {
    int ethPacketCount = 0;
    int ipv4PacketCount = 0;
    int ipv6PacketCount = 0;
    int tcpPacketCount = 0;
    int udpPacketCount = 0;
    int dnsPacketCount = 0;
    int httpPacketCount = 0;
    int sslPacketCount = 0;

    void clear() {
        ethPacketCount = ipv4PacketCount = ipv6PacketCount = tcpPacketCount = udpPacketCount =
            dnsPacketCount = httpPacketCount = sslPacketCount = 0;
    }

    void consumePacket(pcpp::Packet& packet) {
        if (packet.isPacketOfType(pcpp::Ethernet)) ethPacketCount++;
        if (packet.isPacketOfType(pcpp::IPv4)) ipv4PacketCount++;
        if (packet.isPacketOfType(pcpp::IPv6)) ipv6PacketCount++;
        if (packet.isPacketOfType(pcpp::TCP)) tcpPacketCount++;
        if (packet.isPacketOfType(pcpp::UDP)) udpPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS)) dnsPacketCount++;
        if (packet.isPacketOfType(pcpp::HTTP)) httpPacketCount++;
        if (packet.isPacketOfType(pcpp::SSL)) sslPacketCount++;
    }

    void printToConsole() {
        std::cout << "Ethernet packet count: " << "-" << ethPacketCount << "-" << std::endl
                  << "IPv4 packet count:     " << "-" << ipv4PacketCount << "-" << std::endl
                  << "IPv6 packet count:     " << "-" << ipv6PacketCount << "-" << std::endl
                  << "TCP packet count:      " << "-" << tcpPacketCount << "-" << std::endl
                  << "UDP packet count:      " << "-" << udpPacketCount << "-" << std::endl
                  << "DNS packet count:      " << "-" << dnsPacketCount << "-" << std::endl
                  << "HTTP packet count:     " << "-" << httpPacketCount << "-" << std::endl
                  << "SSL packet count:      " << "-" << sslPacketCount << "-" << std::endl;
    }
};

std::string getProtocolName(pcpp::ProtocolType protocol) {
    if (protocol == pcpp::Ethernet) { return "Ethernet"; }
    else if (protocol == pcpp::IPv4) { return "IPv4"; }
    else if (protocol == pcpp::IPv6) { return "IPv6"; }
    else if (protocol == pcpp::TCP) { return "TCP"; }
    else if (protocol == pcpp::UDP) { return "UDP"; }
    else if (protocol == pcpp::HTTP) { return "HTTP"; }
    else if (protocol == pcpp::SSL) { return "SSL"; }
    else if (protocol == pcpp::ARP) { return "ARP"; }
    else if (protocol == pcpp::ICMP) { return "ICMP"; }
    else if (protocol == pcpp::DNS) { return "DNS"; }
    else if (protocol == pcpp::PPPoE) { return "PPPoE"; }
    else if (protocol == pcpp::IGMP) { return "IGMP"; }
    else if (protocol == pcpp::GRE) { return "GRE"; }
    else if (protocol == pcpp::VLAN) { return "VLAN"; }
    else if (protocol == pcpp::SIP) { return "SIP"; }
    else if (protocol == pcpp::SDP) { return "SDP"; }
    else if (protocol == pcpp::DHCP) { return "DHCP"; }
    else if (protocol == pcpp::PacketTrailer) { return "Packet Trailer"; }
    else if (protocol == pcpp::UnknownProtocol) { return "Unknown"; }
    else { return "Other"; }
}

pcpp::AndFilter filterFunc(pcpp::AndFilter theFilter) {
    std::string pFilterList;
    int pCount = 0;

    std::cout << "choose Protocols/Ports, type \"finish\" to stop: " << std::endl;
    std::cout << "Protocols: \"Ethernet\", \"IPv4\", \"IPv6\", \"TCP\", \"UDP\", \"ICMP\", \"ARP\". "
              << "\nPorts: \"80\", \"22\", \"53\"." << std::endl;
    std::cout << "Enter: ";
    std::getline(std::cin, pFilterList);

    std::stringstream ss(pFilterList);
    std::string pName;

    while (getline(ss, pName, ' ')) {
        std::string upperPName = pName;
        std::transform(upperPName.begin(), upperPName.end(), upperPName.begin(), ::toupper);

        if ((upperPName == "FINISH") || (upperPName == "FINISHED")) {
            break;
        }

        if (upperPName == "ETHERNET") {
            theFilter.addFilter(new pcpp::ProtoFilter(pcpp::Ethernet));
            pCount++;
        } else if (upperPName == "UDP") {
            theFilter.addFilter(new pcpp::ProtoFilter(pcpp::UDP));
            pCount++;
        } else if (upperPName == "IPV4") {
            theFilter.addFilter(new pcpp::ProtoFilter(pcpp::IPv4));
            pCount++;
        } else if (upperPName == "IPV6") {
            pcpp::ProtoFilter protocolFilter(pcpp::IPv6);
            theFilter.addFilter(new pcpp::ProtoFilter(pcpp::IPv6));
            pCount++;
        } else if (upperPName == "TCP") {
            theFilter.addFilter(new pcpp::ProtoFilter(pcpp::TCP));
            pCount++;
        } else if (upperPName == "ICMP") {
            theFilter.addFilter(new pcpp::ProtoFilter(pcpp::ICMP));
            pCount++;
        } else if (upperPName == "ARP") {
            theFilter.addFilter(new pcpp::ProtoFilter(pcpp::ARP));
            pCount++;
        } else if (upperPName == "80") {
            theFilter.addFilter(new pcpp::PortFilter(80, pcpp::SRC_OR_DST));
            pCount++;
        } else if (upperPName == "22") {
            theFilter.addFilter(new pcpp::PortFilter(22, pcpp::SRC_OR_DST));
            pCount++;
        } else if (upperPName == "53") {
            theFilter.addFilter(new pcpp::PortFilter(53, pcpp::SRC_OR_DST));
            pCount++;
        } else {
            std::cout << "Invalid input: " << pName << std::endl;
        }
    }

    if (pCount > 8) 
    {
        std::cout << "Invalid filter list" << std::endl;
        std::cout << "NO filter" << std::endl;
        theFilter.addFilter(new pcpp::ProtoFilter(pcpp::Ethernet));
        return theFilter;
    }

    if (pCount == 0) 
    {
        theFilter.addFilter(new pcpp::ProtoFilter(pcpp::Ethernet));
        std::cout << "NO filter" << std::endl;
    }

    return theFilter;
}

void processPackets(pcpp::RawPacketVector& packetVector) {
    PacketStats stats;

    // Sort packets by timestamp
    std::sort(packetVector.begin(), packetVector.end(), [](const pcpp::RawPacket* a, const pcpp::RawPacket* b) {
        timespec tsA = a->getPacketTimeStamp();
        timespec tsB = b->getPacketTimeStamp();
        return (tsA.tv_sec < tsB.tv_sec) || (tsA.tv_sec == tsB.tv_sec && tsA.tv_nsec < tsB.tv_nsec);
    });

    // Iterate through packets
    for (size_t i = 0; i < packetVector.size(); i++) {
        pcpp::Packet parsedPacket(packetVector.at(i));

        std::cout << "Packet " << i << " - Timestamp: "
                  << packetVector.at(i)->getPacketTimeStamp().tv_sec << "."
                  << packetVector.at(i)->getPacketTimeStamp().tv_nsec / 1000 << "\n";

        // Iterate over all layers
        pcpp::Layer* layer = parsedPacket.getFirstLayer();
        while (layer != nullptr) {
            std::cout << "* Layer: " << getProtocolName(layer->getProtocol()) << std::endl;
            layer = layer->getNextLayer();
        }

        stats.consumePacket(parsedPacket);  // Count packet types
    }

    std::cout << "***** RESULTS *****" << std::endl;
    stats.printToConsole();
}

bool menuFilter() {
    char iFilter;
    std::cout << "Filter? Y/N: ";
    std::cin >> iFilter;

    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(100, '\n');
        std::cout << "Invalid input.  Assuming no filter." << std::endl;
        return false;
    }

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    switch (iFilter) {
        case 'y':
        case 'Y':
            return true;
        case 'n':
        case 'N':
            return false;
        default:
            std::cout << "Invalid input.  Assuming no filter." << std::endl;
            return false;
    }
}

int sniffSniff(const std::string& source, bool isLive) {
    pcpp::RawPacketVector packetVector;
    std::string tCaptureString;
    int tCaptureInteger = 10;

    if (isLive) {
        auto* device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(source);
        if (device == nullptr) {
            std::cerr << "Cannot find interface" << std::endl;
            return 1;
        }

        // Interface Information
        std::cout << "+++++++++++ Interface info +++++++++++" << std::endl
                  << "+-- Interface name: " << device->getName() << "           --+" << std::endl
                  << "+-- Interface description: " << device->getDesc() << "        --+" << std::endl
                  << "+-- MAC address: " << device->getMacAddress() << " --+" << std::endl
                  << "+-- Default gateway: " << device->getDefaultGateway() << "      --+" << std::endl
                  << "+-- Interface MTU: " << device->getMtu() << "            --+" << std::endl;

        if (!device->getDnsServers().empty()) {
            std::cout << "+-- DNS server: " << device->getDnsServers().front() << "           --+" << std::endl;
        }
        std::cout << "++++++++++++++++++++++++++++++++++++++" << std::endl;

        if (!device->open()) {
            std::cerr << "Cannot open device" << std::endl;
            return 1;
        }

        // Setting filter
        pcpp::AndFilter filter;
        if (menuFilter()) {
            filter = filterFunc(filter);
            device->setFilter(filter);
        }

        std::cout << "For how much time do you want to capture traffic in seconds(10 seconds default)?"
                  << std::endl;
        std::cin >> tCaptureString;

        if (!tCaptureString.empty()) {
            bool isValid = true;
            for (char c : tCaptureString) {
                if (!isdigit(c)) {
                    std::cout << "Invalid input, using default(10 sec)" << std::endl;
                    isValid = false;
                    break;
                }
            }
            if (isValid) {
                tCaptureInteger = std::stoi(tCaptureString);
                if (tCaptureInteger > 3600) {
                    tCaptureInteger = 3600;
                    std::cout << "To much time, setting to 3600 sec(max)" << std::endl;
                }
            }
        } else {
            std::cout << "Using default(10 sec)" << std::endl;
        }

        std::cout << "Capturing packets for " << tCaptureInteger << " seconds..." << std::endl;
        device->startCapture(packetVector);
        pcpp::multiPlatformSleep(tCaptureInteger);
        device->stopCapture();
        device->close();
        std::cout << "***** Capture Completed *****" << std::endl;

    } else {
        // READ FROM PCAP FILE
        std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(source));

        if (!reader->open()) {
            std::cerr << "Error opening PCAP file: " << source << std::endl;
            return 1;
        }

        pcpp::AndFilter filter;
        // Setting filter
        if (menuFilter()) {
            filter = filterFunc(filter);
            reader->setFilter(filter);
            std::cout << "Filter ON" << std::endl;
        }

        pcpp::RawPacket* rawPacket;  
        while (true) {
            rawPacket = new pcpp::RawPacket(); 
            if (!reader->getNextPacket(*rawPacket)) {
                delete rawPacket; 
                break;
            }
            packetVector.pushBack(rawPacket);
        }
        reader->close();
    }

    processPackets(packetVector);

    for (pcpp::RawPacket* packet : packetVector) {
        delete packet;
    }
    packetVector.clear();

    return 0;
}


bool isBlank(char c) {
    return std::isspace(static_cast<unsigned char>(c));
}

int menu() {
    static int menuCount = 0;
    menuCount++;

    if (menuCount > 1)
        std::cout << "Welcome back!" << std::endl;
    else
        std::cout << "Welcome !" << std::endl;
    char menuInput;
    std::cout << "*               The menu bar                  *" << std::endl
              << "+              ˜‾‾‾‾‾‾‾‾‾‾‾‾˜                 +" << std::endl
              << "+'E' / 'e' = Example pcap/ng file             +" << std::endl
              << "+'P' / 'p' = Personal pcap/ng file            +" << std::endl
              << "+'S' / 's' = Sniff interface(IPv4 is required)+" << std::endl
              << "+'Q' / 'q' = Quit...                          +" << std::endl
              << "*+++++++++++++++++++++++++++++++++++++++++++++*" << std::endl
              << "Enter character: ";

    std::cin >> menuInput;

    if (std::cin.fail() || isBlank(menuInput)) 
    {    // if (std::cin.fail() || isBlank(menuInput))
        std::cin.clear();
        std::cin.ignore(100, '\n');
        std::cerr << "Invalid input. Please try again.\n";
        return menu();
    }


    switch (menuInput) {
        case 'E':
        case 'e':
            std::cout << "You chose the \"Example\" option." << std::endl;
            sniffSniff("input.pcap", false);
            break;

        case 'P':
        case 'p':
        {
            std::string fName;
            std::cout << "You chose the \"Personal\" option." << std::endl;
            std::cout << "---Write pcap file full name: ";
            std::getline(std::cin, fName);
            sniffSniff(fName, false);
            break;
        }
        case 'S':
        case 's': 
        {
            std::cout << "You chose the \"Sniffing\" option." << std::endl;
            std::string userIP;
            std::cout << "Enter an IP address: ";
            std::cin >> userIP;



            std::cout << "Validating IP address. . . " << std::endl;
            if (isValidIPAddress(userIP)) {
                std::cout << "Valid IP: " << userIP << std::endl;
                sniffSniff(userIP, true);
            } else {
                std::cout << "Invalid IP address!" << std::endl;
                return menu();
            }
            break;
        }

        case 'Q':
        case 'q':
            std::cout << "You chose the \"Quit\" option.\nBye Bye!!" << std::endl;
            return -1;

        default:
            std::cerr << "Invalid choice. Try again." << std::endl;
            return menu();
    }

    return 0;
}

int main(int argc, char* argv[]) {
    std::cout << "   #####     ######   #######      #######  " << std::endl
              << " #       #  #       #    #        #       # " << std::endl
              << "#           #  #####     #        #  #####  " << std::endl
              << "#           #  #         #   ===  #  #      " << std::endl
              << "#           #   #        #        #  #      " << std::endl
              << "#       #   #    #       #        #  #      " << std::endl
              << " ######     #     #      #        #  #      " << std::endl
              << "--------------------------------------------" << std::endl;
    menu();
    return 0;
}

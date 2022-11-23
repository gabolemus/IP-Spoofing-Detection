use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::fs::File;

fn main() {
    let network_traffic = "../tcpdump/network-traffic.pcap";
    let file = File::open(network_traffic).unwrap();

    let mut blocks_count = 0;
    let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                println!("");
                blocks_count += 1;

                match block {
                    PcapBlockOwned::LegacyHeader(_header) => {
                        // Print the header
                        // println!("got header: {:?}", header);

                        // Ignore the header for now
                        blocks_count -= 1;
                    }

                    PcapBlockOwned::Legacy(block) => {
                        // Print the block
                        println!("Got block #{}: {:?}", blocks_count, block);
                    }

                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            }

            Err(PcapError::Eof) => break,

            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }

            Err(err) => panic!("An error while reading the file: {:?}", err),
        }
    }

    println!("\nNumber of blocks: {}", blocks_count);
}

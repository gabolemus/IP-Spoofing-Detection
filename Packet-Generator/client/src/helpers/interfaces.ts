/** This file contains all the interfaces used in the project. */

export interface Response {
  success: boolean;
  message: string;
}

export interface PacketData {
  setEvilBit: boolean;
  sourceIP?: string;
  destinationIP: string;
  infinitePackets: boolean;
  packetInterval: number;
  port: number;
  payload: string;
}

export interface ExtraPacketData {
  packetData: PacketData;
  packetCount: number;
  randomSourceIP?: boolean;
}

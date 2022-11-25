/** This file contains the helper functions used in the project. */

import axios from 'axios';
import { ExtraPacketData, PacketData, Response } from './interfaces';

/** Style constants */
const STYLES = {
  maxWidth: '90%',
};

/** Color palette */
const PALETTE = {
  darkBlue: '#22577e',
  blue: '#5584ac',
  lightCyan: '#95d1cc',
  beige: '#f6f2d4',
  white: '#ffffff',
};

/** Check if the provided string can be parsed as an IPv4 address with a RegEx */
const isIPv4 = (str: string): boolean => {
  const regEx =
    /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

  return regEx.test(str);
};

/** POST request to send a single spoofed packet */
const sendSingleSpoofedPacket = async (
  packet: PacketData
): Promise<Response> => {
  // Send the POST request
  return await sendPostRequest('single-spoofed', packet);
};

/** POST request to send multiple spoofed packets */
const sendMultipleSpoofedPackets = async (
  packet: ExtraPacketData
): Promise<Response> => {
  // Send the POST request
  return await sendPostRequest('multiple-spoofed/start', packet);
};

/** POST request to stop sending multiple spoofed or legitimate packets */
const stopSendingPackets = async (): Promise<Response> => {
  // Send the POST request
  return await sendPostRequest('multiple-spoofed/stop', {});
};

/** POST request to send a single legitimate packet */
const sendSingleLegitimatePacket = async (
  packet: PacketData
): Promise<Response> => {
  // Send the POST request
  return await sendPostRequest('single-spoofed', packet);
};

/** POST request to send multiple legitimate packets */
const sendMultipleLegitimatePackets = async (
  packet: ExtraPacketData
): Promise<Response> => {
  // Send the POST request
  return await sendPostRequest('multiple-spoofed/start', packet);
};

/** Send a general POST request to the specified endpoint */
const sendPostRequest = async (
  endpoint: string,
  data: PacketData | ExtraPacketData | Record<string, never>
): Promise<Response> => {
  // Create the response object from the provided packet data
  const response = await axios.post(`http://localhost:8080/${endpoint}`, data);

  // Check the response code
  if (response.status === 200) {
    return createResponse(true, 'Request sent successfully!');
  } else {
    return createResponse(false, 'Error sending request!');
  }
};

/** Create a response object */
const createResponse = (success: boolean, message: string): Response => ({
  success,
  message,
});

/** General helpers */
const helpers = {
  STYLES,
  PALETTE,
  isIPv4,
  sendSingleSpoofedPacket,
  sendMultipleSpoofedPackets,
  stopSendingPackets,
  sendSingleLegitimatePacket,
  sendMultipleLegitimatePackets,
};

export default helpers;

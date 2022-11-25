/* eslint-disable @typescript-eslint/no-non-null-assertion */
import React, { useState } from 'react';
import helpers from '../../helpers/helpers';
import {
  ExtraPacketData,
  PacketData,
  Response,
} from '../../helpers/interfaces';
import CheckBoxInputGroup from '../atoms/CheckBoxInputGroup';
import NumberInputGroup from '../atoms/NumberInputGroup';
import PrimaryBtn from '../atoms/PrimaryBtn';
import TextAreaInputGroup from '../atoms/TextAreaInputGroup';
import TextInputGroup from '../atoms/TextInputGroup';
import './PacketGeneratorCard.scss';

/** Props for the PacketGeneratorCard component */
interface PacketGeneratorCardProps {
  /** The title of the card */
  title: string;
  /** The id of the card */
  cardId: number;
  /** Whether or not the generator creates spoofed packets */
  spoofPackets: boolean;
  /** Function to indicate that infinite packets are being sent */
  setInfinitePackets: (infinitePackets: boolean) => void;
  /** Infinite packets */
  infinitePackets: boolean;
  /** Function to toggle the infinite packets checkbox */
  toggleInfinitePackets: () => void;
  /** Random source IP */
  randomSourceIp: boolean;
  /** Function to toggle the random source IP checkbox */
  toggleRandomSourceIp: () => void;
  /** Infinite packets toggle reference */
  infinitePacketsToggleRef: React.RefObject<HTMLInputElement>;
  /** Random IP address source toggle reference */
  randomSourceIpToggleRef: React.RefObject<HTMLInputElement>;
}

const PacketGeneratorCard = (props: PacketGeneratorCardProps) => {
  // State
  const [canSendPkts, setCanSendPkts] = useState(false);
  const [srcIPAddr, setSrcIPAddr] = useState('');
  const [dstIPAddr, setDstIPAddr] = useState('');
  const [payload, setPayload] = useState('');
  const [pktAmount, setPktAmount] = useState(1);
  const [pktDelay, setPktDelay] = useState(500);

  // Refs

  // Functions
  /** Toggle the random source address checkbox */
  const toggleRandomSrcAddr = () => {
    if (
      (srcIPAddr !== '' && dstIPAddr !== '') ||
      (!props.randomSourceIp && dstIPAddr !== '')
    ) {
      setCanSendPkts(true);
    } else {
      setCanSendPkts(false);
    }

    props.toggleRandomSourceIp();
  };

  /** Toggle the send infinite packets checkbox */
  const toggleSendInfPkts = () => {
    props.toggleInfinitePackets();
  };

  /** Check that both IP addresses are set to toggle the send button */
  const checkIPsSrc = (ip: string) => {
    if (
      (ip !== '' && helpers.isIPv4(ip) && dstIPAddr !== '') ||
      (props.randomSourceIp && dstIPAddr !== '')
    ) {
      setCanSendPkts(true);
    } else {
      setCanSendPkts(false);
    }

    setSrcIPAddr(ip);
  };

  /** Check that both IP addresses are set to toggle the send button */
  const checkIPsDst = (ip: string) => {
    if (
      (srcIPAddr !== '' && ip !== '' && helpers.isIPv4(ip)) ||
      (props.randomSourceIp && ip !== '' && helpers.isIPv4(ip))
    ) {
      setCanSendPkts(true);
    } else {
      setCanSendPkts(false);
    }

    setDstIPAddr(ip);
  };

  /** Send the packets */
  const sendPackets = async () => {
    changeBtnTextPerm('Enviando paquetes...');

    if (props.infinitePackets) {
      props.setInfinitePackets(true);
    } else {
      props.setInfinitePackets(false);

      // Create the packet
      const packet: PacketData = {
        setEvilBit: true,
        ...(srcIPAddr !== '' &&
          !props.randomSourceIp && { sourceIP: srcIPAddr }),
        destinationIP: dstIPAddr,
        port: 43390,
        data: payload,
      };

      if (pktAmount == 1) {
        // Attempt to send a single packet
        if (props.spoofPackets) {
          // Send spoofed packet
          const response: Response = await helpers.sendSingleSpoofedPacket(
            packet
          );

          if (response.success) {
            changeBtnTextTemp(
              'Paquete enviado exitosamente',
              'Enviar paquetes'
            );
          } else {
            changeBtnTextTemp('Error al enviar el paquete', 'Enviar paquetes');
          }
        } else {
          // Send packet
          const response: Response = await helpers.sendSingleLegitimatePacket({
            ...packet,
            setEvilBit: false,
          });

          if (response.success) {
            changeBtnTextTemp(
              'Paquete enviado exitosamente',
              'Enviar paquetes'
            );
          } else {
            changeBtnTextTemp('Error al enviar el paquete', 'Enviar paquetes');
          }
        }
      } else {
        // Attempt to send multiple packets
        if (props.spoofPackets) {
          // Create the packet
          const packet: ExtraPacketData = {
            packetCount: pktAmount,
            randomSourceIP: props.randomSourceIp,
            packetData: {
              setEvilBit: true,
              ...(srcIPAddr !== '' && { sourceIP: srcIPAddr }),
              destinationIP: dstIPAddr,
              port: 43390,
              data: payload,
            },
          };

          // Send multiple packets
          const response: Response = await helpers.sendMultipleSpoofedPackets(
            packet
          );

          if (response.success) {
            changeBtnTextTemp(
              'Paquetes enviados exitosamente',
              'Enviar paquetes'
            );
          } else {
            changeBtnTextTemp(
              'Error al enviar los paquetes',
              'Enviar paquetes'
            );
          }
        } else {
          // Create the packet
          const packet: ExtraPacketData = {
            packetCount: pktAmount,
            randomSourceIP: props.randomSourceIp,
            packetData: {
              setEvilBit: false,
              ...(srcIPAddr !== '' && { sourceIP: srcIPAddr }),
              destinationIP: dstIPAddr,
              port: 43390,
              data: payload,
            },
          };

          // Send multiple packets
          const response: Response =
            await helpers.sendMultipleLegitimatePackets(packet);

          if (response.success) {
            changeBtnTextTemp(
              'Paquetes enviados exitosamente',
              'Enviar paquetes'
            );
          } else {
            changeBtnTextTemp(
              'Error al enviar los paquetes',
              'Enviar paquetes'
            );
          }
        }
      }
    }
  };

  /** Change the text of the button temporarily */
  const changeBtnTextTemp = (text: string, permanentText: string) => {
    // Get the button by its id
    const btn = document.getElementById(`btn-${props.cardId}`);

    // Add the btn-ok class to the button
    btn!.classList.add('btn-ok');

    // Disable the button
    btn!.setAttribute('disabled', 'true');

    // Change the text
    btn!.innerHTML = text;

    // After 2.5 seconds, change the text back
    setTimeout(() => {
      btn!.innerHTML = permanentText;

      // Remove the btn-ok class from the button
      btn!.classList.remove('btn-ok');

      // Enable the button
      btn!.removeAttribute('disabled');
    }, 2500);
  };

  /** Change the text of the button permanently */
  const changeBtnTextPerm = (text: string) => {
    // Get the button by its id
    const btn = document.getElementById(`btn-${props.cardId}`);

    // Change the text
    btn!.innerHTML = text;
  };

  /** Set packet payload */
  const setPacketPayload = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setPayload(e.target.value);
  };

  /** Set the packet amount */
  const setPacketAmount = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPktAmount(parseInt(e.target.value));
  };

  /** Set the packet delay */
  const setPacketDelay = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPktDelay(parseInt(e.target.value));
  };

  return (
    <div className="card">
      <h2 className="card-title">{props.title}</h2>
      <div className="card-content">
        <div className="input-row">
          <TextInputGroup
            label="IP de Origen"
            placeholder="E.g. 123.123.123.123"
            setIP={checkIPsSrc}
            disabled={props.randomSourceIp}
          />
          <TextInputGroup
            label="Dirección IP de Destino"
            placeholder="E.g. 123.123.123.123"
            setIP={checkIPsDst}
          />
        </div>
        <div className="input-row">
          <NumberInputGroup
            label="Cantidad de Paquetes"
            width={33}
            disabled={props.infinitePackets}
            defaultValue={1}
            setCount={setPacketAmount}
          />
          <CheckBoxInputGroup
            label="¿Paquetes Infinitos?"
            toggle={toggleSendInfPkts}
            checkboxRef={props.infinitePacketsToggleRef}
          />
          <NumberInputGroup
            label="Retardo entre Paquetes (Milisegundos)"
            width={33}
            defaultValue={500}
            setCount={setPacketDelay}
          />
          <CheckBoxInputGroup
            label="¿IP de Origen aleatoria?"
            toggle={toggleRandomSrcAddr}
            checkboxRef={props.randomSourceIpToggleRef}
          />
        </div>
        <div className="input-row">
          <TextAreaInputGroup
            label="Datos del paquete"
            width={100}
            setPayload={setPacketPayload}
          />
        </div>
        <PrimaryBtn
          title="Enviar Paquetes"
          btnId={props.cardId}
          disabled={!canSendPkts}
          onClick={sendPackets}
        />
      </div>
    </div>
  );
};

export default PacketGeneratorCard;

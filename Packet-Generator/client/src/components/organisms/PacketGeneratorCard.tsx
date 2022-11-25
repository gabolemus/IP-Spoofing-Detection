import React, { useState } from 'react';
import helpers from '../../helpers/helpers';
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
  const sendPackets = () => {
    if (props.infinitePackets) {
      props.setInfinitePackets(true);
    }
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
          />
          <CheckBoxInputGroup
            label="¿IP de Origen aleatoria?"
            toggle={toggleRandomSrcAddr}
            checkboxRef={props.randomSourceIpToggleRef}
          />
        </div>
        <div className="input-row">
          <TextAreaInputGroup label="Datos del paquete" width={100} />
        </div>
        <PrimaryBtn
          title="Enviar Paquetes"
          disabled={!canSendPkts}
          onClick={sendPackets}
        />
      </div>
    </div>
  );
};

export default PacketGeneratorCard;

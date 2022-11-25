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
}

const PacketGeneratorCard = (props: PacketGeneratorCardProps) => {
  // State
  const [randomSrcAddr, setRandomSrcAddr] = useState(false);
  const [sendInfPkts, setSendInfPkts] = useState(false);
  const [canSendPkts, setCanSendPkts] = useState(false);
  const [srcIPAddr, setSrcIPAddr] = useState('');
  const [dstIPAddr, setDstIPAddr] = useState('');

  // Functions
  /** Toggle the random source address checkbox */
  const toggleRandomSrcAddr = () => {
    if (
      (srcIPAddr !== '' && dstIPAddr !== '') ||
      (!randomSrcAddr && dstIPAddr !== '')
    ) {
      setCanSendPkts(true);
    } else {
      setCanSendPkts(false);
    }

    setRandomSrcAddr(!randomSrcAddr);
  };

  /** Toggle the send infinite packets checkbox */
  const toggleSendInfPkts = () => {
    setSendInfPkts(!sendInfPkts);
  };

  /** Check that both IP addresses are set to toggle the send button */
  const checkIPsSrc = (ip: string) => {
    if (
      (ip !== '' && helpers.isIPv4(ip) && dstIPAddr !== '') ||
      (randomSrcAddr && dstIPAddr !== '')
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
      (randomSrcAddr && ip !== '' && helpers.isIPv4(ip))
    ) {
      setCanSendPkts(true);
    } else {
      setCanSendPkts(false);
    }

    setDstIPAddr(ip);
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
            disabled={randomSrcAddr}
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
            disabled={sendInfPkts}
            defaultValue={1}
          />
          <CheckBoxInputGroup
            label="¿Paquetes Infinitos?"
            toggle={toggleSendInfPkts}
          />
          <NumberInputGroup
            label="Retardo entre Paquetes (Milisegundos)"
            width={33}
            defaultValue={500}
          />
          <CheckBoxInputGroup
            label="¿IP de Origen aleatoria?"
            toggle={toggleRandomSrcAddr}
          />
        </div>
        <div className="input-row">
          <TextAreaInputGroup label="Datos del paquete" width={100} />
        </div>
        <PrimaryBtn title="Enviar Paquetes" disabled={!canSendPkts} />
      </div>
    </div>
  );
};

export default PacketGeneratorCard;

/* eslint-disable @typescript-eslint/no-non-null-assertion */
import React, { useState } from 'react';
import CancelBtn from '../atoms/CancelBtn';
import PacketGeneratorCard from '../organisms/PacketGeneratorCard';
import MainPageTemplate from '../templates/MainPageTemplate';
import { Response } from '../../helpers/interfaces';
import helpers from '../../helpers/helpers';

const PacketGeneratorPage = () => {
  // State
  const [canStopPackets, setCanStopPackets] = useState(false);
  const [rndmSpoofedSrcIP, setRndmSpoofedSrcIP] = useState(false);
  const [sendInfSpoofedPkts, setSendInfSpoofedPkts] = useState(false);
  const [rndmLegitSrcIP, setRndmLegitSrcIP] = useState(false);
  const [sendInfLegitPkts, setSendInfLegitPkts] = useState(false);

  // Refs
  const infSpoofedPktsRef = React.createRef<HTMLInputElement>();
  const rndmSpoofedPktsIPSrcRef = React.createRef<HTMLInputElement>();
  const infLegitPktsRef = React.createRef<HTMLInputElement>();
  const rndmLegitPktsIPSrcRef = React.createRef<HTMLInputElement>();

  /** Reset the state to stop sending packets */
  const resetState = () => {
    if (infLegitPktsRef.current?.checked) {
      infLegitPktsRef.current?.click();
    }

    if (rndmLegitPktsIPSrcRef.current?.checked) {
      rndmLegitPktsIPSrcRef.current?.click();
    }

    if (infSpoofedPktsRef.current?.checked) {
      infSpoofedPktsRef.current?.click();
    }

    if (rndmSpoofedPktsIPSrcRef.current?.checked) {
      rndmSpoofedPktsIPSrcRef.current?.click();
    }

    if (rndmSpoofedSrcIP) {
      setRndmSpoofedSrcIP(false);
    }

    if (sendInfSpoofedPkts) {
      setSendInfSpoofedPkts(false);
    }

    if (rndmLegitSrcIP) {
      setRndmLegitSrcIP(false);
    }

    if (sendInfLegitPkts) {
      setSendInfLegitPkts(false);
    }

    stopSendingPackets();
    setCanStopPackets(false);
  };

  /** Stop sending packets */
  const stopSendingPackets = async () => {
    const response: Response = await helpers.stopSendingPackets();

    evaluateResponse(response);
  };

  /** Evaluate response */
  const evaluateResponse = (response: Response) => {
    if (response.success) {
      changeBtnTextTemp(
        'Envío de paquetes detenido exitosamente',
        'Detener el envío de paquetes'
      );
    } else {
      changeBtnTextTemp(
        'Error al detener el envío de paquetes',
        'Detener el envío de paquetes'
      );
    }
  };

  /** Change the text of the button temporarily */
  const changeBtnTextTemp = (text: string, permanentText: string) => {
    // Get the button by its id
    const btn = document.getElementById('stop-button');

    // Disable the button
    btn!.setAttribute('disabled', 'true');

    // Change the text
    btn!.innerHTML = text;

    // After 2.5 seconds, change the text back
    setTimeout(() => {
      btn!.innerHTML = permanentText;
    }, 2500);
  };

  return (
    <MainPageTemplate>
      <div className="main-page-window">
        <h1 className="title">Generador de Paquetes TCP/IP</h1>
        <PacketGeneratorCard
          title="Envío de Paquetes Spoofeados"
          cardId={1}
          spoofPackets={true}
          setInfinitePackets={setCanStopPackets}
          infinitePackets={sendInfSpoofedPkts}
          toggleInfinitePackets={() =>
            setSendInfSpoofedPkts(!sendInfSpoofedPkts)
          }
          randomSourceIp={rndmSpoofedSrcIP}
          toggleRandomSourceIp={() => setRndmSpoofedSrcIP(!rndmSpoofedSrcIP)}
          infinitePacketsToggleRef={infSpoofedPktsRef}
          randomSourceIpToggleRef={rndmSpoofedPktsIPSrcRef}
        />
        <PacketGeneratorCard
          title="Envío de Paquetes Legítimos"
          cardId={2}
          spoofPackets={false}
          setInfinitePackets={setCanStopPackets}
          infinitePackets={sendInfLegitPkts}
          toggleInfinitePackets={() => setSendInfLegitPkts(!sendInfLegitPkts)}
          randomSourceIp={rndmLegitSrcIP}
          toggleRandomSourceIp={() => setRndmLegitSrcIP(!rndmLegitSrcIP)}
          infinitePacketsToggleRef={infLegitPktsRef}
          randomSourceIpToggleRef={rndmLegitPktsIPSrcRef}
        />
      </div>
      <CancelBtn
        title="Detener el envío de paquetes"
        disabled={!canStopPackets}
        onClick={resetState}
      />
    </MainPageTemplate>
  );
};

export default PacketGeneratorPage;

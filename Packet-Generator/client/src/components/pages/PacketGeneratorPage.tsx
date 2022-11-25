import React, { useState } from 'react';
import CancelBtn from '../atoms/CancelBtn';
import PacketGeneratorCard from '../organisms/PacketGeneratorCard';
import MainPageTemplate from '../templates/MainPageTemplate';

const PacketGeneratorPage = () => {
  // State
  const [canStopPackets, setCanStopPackets] = useState(false);

  return (
    <MainPageTemplate>
      <div className="main-page-window">
        <h1 className="title">Generador de Paquetes TCP/IP</h1>
        <PacketGeneratorCard title="Envío de Paquetes Spoofeados" />
        <PacketGeneratorCard title="Envío de Paquetes Legítimos" />
      </div>
      <CancelBtn
        title="Detener el envío de paquetes"
        disabled={!canStopPackets}
      />
    </MainPageTemplate>
  );
};

export default PacketGeneratorPage;

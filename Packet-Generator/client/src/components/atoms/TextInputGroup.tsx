import React, { useState } from 'react';
import helpers from '../../helpers/helpers';
import './InputGroup.scss';

/** Props */
interface TextInputGroupProps {
  /** The label of the input */
  label: string;
  /** Placeholder of the input */
  placeholder?: string;
  /** Whether the input is disabled or not */
  disabled?: boolean;
  /** Function to set the IP address */
  setIP: (ip: string) => void;
}

const TextInputGroup = (props: TextInputGroupProps) => {
  // State
  const [errorMsg, setErrorMsg] = useState('');

  /** Check if the text provided can be parsed as an IP address */
  const isIP = (e: React.ChangeEvent<HTMLInputElement>) => {
    const ipRegex = helpers.isIPv4(e.target.value);

    if (ipRegex) {
      setErrorMsg('');
      props.setIP(e.target.value);
    } else {
      setErrorMsg('Por favor, ingrese una dirección IPv4 válida');
      props.setIP('');
    }
  };

  return (
    <div className="input-group w-49">
      <label htmlFor="source-ip">{props.label}</label>
      <input
        type="text"
        id="source-ip"
        placeholder={props.placeholder || 'Por favor, ingrese un valor'}
        disabled={props.disabled}
        onChange={isIP}
      />
      <small className="error-message">{errorMsg}</small>
    </div>
  );
};

export default TextInputGroup;

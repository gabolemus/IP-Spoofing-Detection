import React from 'react';

/** Props */
interface TextAreaInputGroupProps {
  /** The label of the input */
  label: string;
  /** Width of the input group */
  width: number;
  /** Function to set the packet payload */
  setPayload: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
}

const TextAreaInputGroup = (props: TextAreaInputGroupProps) => {
  return (
    <div className={`input-group w-${props.width}`}>
      <label htmlFor="packet-data">{props.label}</label>
      <textarea id="packet-data" onChange={props.setPayload} />
    </div>
  );
};

export default TextAreaInputGroup;

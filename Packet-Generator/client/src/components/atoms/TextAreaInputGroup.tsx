import React from 'react';

/** Props */
interface TextAreaInputGroupProps {
  /** The label of the input */
  label: string;
  /** Width of the input group */
  width: number;
}

const TextAreaInputGroup = (props: TextAreaInputGroupProps) => {
  return (
    <div className={`input-group w-${props.width}`}>
      <label htmlFor="packet-data">{props.label}</label>
      <textarea id="packet-data" />
    </div>
  );
};

export default TextAreaInputGroup;

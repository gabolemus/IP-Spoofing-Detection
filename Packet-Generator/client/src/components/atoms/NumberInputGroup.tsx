import React from 'react';

/** Props */
interface NuberInputGroupProps {
  /** The label of the input */
  label: string;
  /** Width of the input group */
  width: number;
  /** Whether the input is disabled or not */
  disabled?: boolean;
  /** Default value of the input */
  defaultValue?: number;
}

const NumberInputGroup = (props: NuberInputGroupProps) => {
  /** Set correct value (default) if the one passed is not a number, is less than 0 or is undefined */
  const correctValue = (value: number | undefined) => {
    if (value === undefined || value < 0 || isNaN(value)) {
      return props.defaultValue ?? 0;
    }

    return value;
  };

  return (
    <div className={`input-group w-${props.width}`}>
      <label htmlFor="packet-count">{props.label}</label>
      <input
        type="number"
        id="packet-count"
        min={1}
        defaultValue={props.defaultValue || 1}
        step={1}
        disabled={props.disabled}
        onChange={(e) => {
          const value = correctValue(parseInt(e.target.value));
          e.target.value = value.toString();
        }}
      />
      <small className="error-message" />
    </div>
  );
};

export default NumberInputGroup;

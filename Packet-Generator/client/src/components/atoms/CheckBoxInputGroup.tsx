import React from 'react';

/** Props */
interface CheckBoxInputGroupProps {
  /** The label of the input */
  label: string;
  /** Reference to the checkbox */
  checkboxRef: React.RefObject<HTMLInputElement>;
  /** Function to toggle the checkbox */
  toggle: () => void;
}

const CheckBoxInputGroup = (props: CheckBoxInputGroupProps) => {
  return (
    <div className="input-group w-15">
      <label htmlFor="infinite-packets">{props.label}</label>
      <input
        type="checkbox"
        id="infinite-packets"
        onClick={props.toggle}
        ref={props.checkboxRef}
      />
    </div>
  );
};

export default CheckBoxInputGroup;

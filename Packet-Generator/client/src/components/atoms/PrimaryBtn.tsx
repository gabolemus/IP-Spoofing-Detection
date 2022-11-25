import React from 'react';
import './Button.scss';

/** Props */
interface PrimaryBtnProps {
  /** The title of the button */
  title: string;
  /** Button number id */
  btnId: number;
  /** Onclick function */
  onClick?: () => void;
  /** Whether the button is disabled or not */
  disabled?: boolean;
}

const PrimaryBtn = (props: PrimaryBtnProps) => {
  return (
    <button
      className="btn btn-primary"
      id={`btn-${props.btnId}`}
      disabled={props.disabled || false}
      onClick={props.onClick}
    >
      {props.title}
    </button>
  );
};

export default PrimaryBtn;

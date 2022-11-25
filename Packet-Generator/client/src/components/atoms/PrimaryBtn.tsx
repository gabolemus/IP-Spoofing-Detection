import React from 'react';
import './Button.scss';

/** Props */
interface PrimaryBtnProps {
  /** The title of the button */
  title: string;
  /** Whether the button is disabled or not */
  disabled?: boolean;
}

const PrimaryBtn = (props: PrimaryBtnProps) => {
  return (
    <button className="btn btn-primary" disabled={props.disabled || false}>
      {props.title}
    </button>
  );
};

export default PrimaryBtn;

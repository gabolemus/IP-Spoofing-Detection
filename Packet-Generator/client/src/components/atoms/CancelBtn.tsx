import React from 'react';

/** Props */
interface CancelBtnProps {
  /** The title of the button */
  title: string;
  /** Whether the button is disabled or not */
  disabled?: boolean;
}

const CancelBtn = (props: CancelBtnProps) => {
  return (
    <button className="stop-button" disabled={props.disabled}>
      {props.title}
    </button>
  );
};

export default CancelBtn;

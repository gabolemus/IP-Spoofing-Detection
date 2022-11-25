import React from 'react';
import './MainPageTemplate.scss';

/** Props for the MainPageTemplate component. */
interface Props {
  /** The children to render inside the template. */
  children: React.ReactNode;
}

const MainPageTemplate = ({ children }: Props) => {
  return <div className="page-template">{children}</div>;
};

export default MainPageTemplate;

import React, {FC} from 'react';
import {Input as AntInput, InputNumber as AntNumber} from "antd";
import {InputProps} from "antd";
import styled, {css} from "styled-components";

const AntPassword = AntInput.Password;

export interface IPropsInput {
    field?: any;
    type?: string;
    placeholder?: string;
    disabled?: boolean;
    background?: string;
    min?: string;
    max?: string;
    width?: string;
    display?: string;
}

const StyledInput: FC<IPropsInput> = (
    {
        field,
        type,
        placeholder,
        disabled,
        background,
        min,
        max,
        width,
        display
    }
) => {
    return (
        <>
            {
                (type === 'text' || type === 'email' || type === undefined) &&
                <_StyledText
                    {...field}
                    disabled={disabled}
                    placeholder={placeholder}
                    width={width}
                    display={display}
                    background={background}
                />
            }
            {
                (type === 'password') &&
                <_StyledPassword
                    {...field}
                    disabled={disabled}
                    placeholder={placeholder}
                    width={width}
                    display={display}
                    background={background}
                />
            }
            {
                (type === 'number') &&
                <_StyledNumber
                    {...field}
                    disabled={disabled}
                    placeholder={placeholder}
                    min={min}
                    max={max}
                    formatter={(value) => `${value}`.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}
                    parser={(value: string) => value.replace(/\$\s?|(,*)/g, '')}
                    width={width}
                    display={display}
                    background={background}
                />
            }
        </>
    );
};

export default StyledInput;

interface _StyledInput extends InputProps {
    display?: string;
    width?: string;
    background?: string;
}

const baseStyles = css`
  //border: solid 2px #e5e6eb;
  //border-radius: 5px;
  //padding: 16px 20px;
  //font-size: 15px;
  width: 100%;
`;

const _StyledText = styled(AntInput)<_StyledInput>`
  ${baseStyles};
  //display: ${(props) => props.display || 'block'};
  //width: ${(props) => props.width || "100%"};
  background: ${(props) => props.background || "#ffffff"};
`;

const _StyledPassword = styled(AntPassword)<_StyledInput>`
  ${baseStyles};
  // display: ${(props) => props.display || 'block'};
  //width: ${(props) => props.width || "100%"};
  background: ${(props) => props.background || "#ffffff"};
`;

const _StyledNumber = styled(AntNumber)<_StyledInput>`
  ${baseStyles};
  // display: ${(props) => props.display || 'block'};
  // width: ${(props) => props.width || "100%"};
  background: ${(props) => props.background || "#ffffff"};
`;
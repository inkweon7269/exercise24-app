import React, {FC} from 'react';
import {Button as AntButton, InputProps} from "antd";
import {SizeType} from "antd/es/config-provider/SizeContext";
import {ButtonHTMLType} from "antd/es/button/button";
import {ButtonType} from "antd/lib/button";
import styled from "styled-components";

export interface IPropsButton {
    text: string;
    type: ButtonType;
    htmlType?: ButtonHTMLType;
    size: SizeType;
    icon?: React.ReactNode;
    block?: boolean;
    loading?: boolean;
    onClick?: any;
}

const StyledButton: FC<IPropsButton> = (
    {
        text,
        type,
        htmlType,
        size,
        icon,
        block,
        loading,
        onClick
    }
) => {
    return (
        <_StyledButton type={type} htmlType={htmlType} size={size}
                       icon={icon}
                       block={block}
                       loading={loading}
                       onClick={onClick}
        >
            {text}
        </_StyledButton>
    );
};

export default StyledButton;

interface _StyledButton extends InputProps {
    background?: string;
}

const _StyledButton = styled(AntButton)<_StyledButton>`
    //background: ${(props) => props.background || "#ffffff"};
`;
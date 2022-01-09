import React, {FC} from 'react';
import {Typography} from 'antd';
import styled from "styled-components";

const AntText = Typography.Paragraph;

interface IPropsError {
    message?: string;
}

const StyledError: FC<IPropsError> = ({message}) => {
    return (
        <_StyledError>{message}</_StyledError>
    );
};

export default StyledError;

const _StyledError = styled(AntText)`
  color: #c02428;
  margin: 0;
`;
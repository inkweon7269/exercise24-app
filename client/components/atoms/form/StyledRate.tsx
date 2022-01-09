import React, {FC} from 'react';
import styled from "styled-components";
import { Rate as AntRate } from "antd";

export interface IPropsRate {
    field?: any;
}

const StyledRate: FC<IPropsRate> = (
    {
        field,
    }
) => {
    return (
        <_StyledRate
            {...field}
        />
    );
};

export default StyledRate;

const _StyledRate = styled(AntRate)`

`
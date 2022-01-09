import React, {FC} from 'react';
import {Switch as AntSwitch} from "antd";
import styled from "styled-components";

export interface IPropsSwitch {
    field?: any;
    chkLabel?: string;
    unChkLabel?: string;
}

const StyledSwitch: FC<IPropsSwitch> = (
    {
        field,
        chkLabel,
        unChkLabel,
    }
) => {
    return (
        <_StyledSwitch
            {...field}
            checkedChildren={chkLabel}
            unCheckedChildren={unChkLabel}
            checked={field.value}
        />
    );
};

export default StyledSwitch;

const _StyledSwitch = styled(AntSwitch)`
    
`;
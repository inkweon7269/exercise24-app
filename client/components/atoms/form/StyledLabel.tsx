import React, {FC} from 'react';
import {Form} from "antd";
import styled from "styled-components";

const AntFormItem = Form.Item;

export interface IPropsLabel {
    label?: string;
    children: React.ReactChild[]
}

const StyledLabel: FC<IPropsLabel> = (
    {
        label,
        children
    }
) => {
    return (
        <_StyledLabel label={label}>
            {children}
        </_StyledLabel>
    );
};

export default StyledLabel;

const _StyledLabel = styled(AntFormItem)`
  .ant-form-item-label {
    padding-bottom: 5px;

    label {
      font-size: 14px;
      color: #8c8c8c;
    }
  }
`
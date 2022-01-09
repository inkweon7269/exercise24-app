import React, {FC} from 'react';
import {DatePicker as AntDate} from "antd";
import styled, {css} from "styled-components";
import moment from "moment";


const AntRangePicker = AntDate.RangePicker;

export interface IPropsDate {
    field?: any;
}

const StyledDate: FC<IPropsDate> = ({
                                        field,
                                    }) => {
    return (
        <_StyledDatePicker
            {...field}
            value={[moment(field.value[0], 'YYYY-MM-DD'), moment(field.value[1], 'YYYY-MM-DD')]}
            disabled={[false, true]}
            onChange={(_, dateString) => field.onChange(dateString)}
        />
    );
};

export default StyledDate;

const _StyledDatePicker = styled(AntRangePicker)`

`;
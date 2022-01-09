import React, {FC} from 'react';
import { Control, Controller } from "react-hook-form";
import StyledError from "../../atoms/form/StyledError";
import StyledDate, {IPropsDate} from "../../atoms/form/StyledDate";
import StyledLabel from "../../atoms/form/StyledLabel";
import moment from "moment";

interface IProps extends IPropsDate {
    control: Control;
    label?: string;
    name: string;
    errorMessage?: string;
}

const DateField:FC<IProps> = ({
    control,
    label,
    name,
    errorMessage,
                              }) => {
    return (
        <Controller
            control={control}
            name={name}
            render={({field}) => (
                <StyledLabel label={label}>
                    <StyledDate
                        field={field}
                    />
                    <StyledError message={errorMessage} />
                </StyledLabel>
            )}
        />
    );
};

export default DateField;
import React, {FC} from 'react';
import {Control, Controller} from "react-hook-form";
import StyledRate, {IPropsRate} from "../../atoms/form/StyledRate";
import StyledLabel from "../../atoms/form/StyledLabel";
import StyledError from "../../atoms/form/StyledError";

interface IPros extends IPropsRate {
    control: Control;
    label?: string;
    name: string;
    errorMessage?: string;
}

const RateField: FC<IPros> = ({
    control,
    label,
    name,
    errorMessage,
    field,
                              }) => {
    return (
        <Controller
            control={control}
            name={name}
            render={({field}) => (
                <StyledLabel label={label}>
                    <StyledRate
                        field={field}
                    />
                    <StyledError message={errorMessage} />
                </StyledLabel>
            )}
        />
    );
};

export default RateField;
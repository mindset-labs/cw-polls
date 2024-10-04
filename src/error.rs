use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Too many poll options")]
    TooManyOptions {},

    #[error("Poll not found")]
    PollNotFound { poll_id: String },

    #[error("Vote not found")]
    VoteNotFound { poll_id: String, vote: String },
}

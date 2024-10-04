use cosmwasm_schema::{cw_serde, QueryResponses};

use crate::state::Poll;

#[cw_serde]
#[serde(rename_all = "lowercase")]
pub struct InstantiateMsg {
    pub admin: Option<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    CreatePoll {
        poll_id: String,
        question: String,
        options: Vec<String>,
    },
    Vote {
        poll_id: String,
        vote: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Option<Poll>)]
    GetPoll {
        poll_id: String,
    },
    #[returns(Vec<Poll>)]
    AllPolls {},
}

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Order, Response, StdResult};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Ballot, Config, Poll, BALLOTS, CONFIG, POLLS};

const CONTRACT_NAME: &str = "crates.io:cw-poll";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = msg.admin.unwrap_or_else(|| info.sender.to_string());
    let config = Config {
        admin: deps.api.addr_validate(&admin)?,
    };

    CONFIG.save(deps.storage, &config)?;

    Ok(
        Response::new()
            .add_attribute("action", "instantiate")
            .add_attribute("admin", config.admin.to_string())
    )
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::CreatePoll { poll_id, question, options } => {
            if options.len() > 10 {
                return Err(ContractError::TooManyOptions {});
            }

            let mut opts: Vec<(String, u64)> = vec![];
            for option in options {
                opts.push((option, 0));
            }
            let poll = Poll {
                creator: info.sender.clone(),
                question,
                options: opts,
            };
            POLLS.save(deps.storage, poll_id.clone(), &poll)?;
            Ok(
                Response::new()
                    .add_attribute("action", "create_poll")
                    .add_attribute("poll_id", poll_id)
                    .add_attribute("creator", info.sender.to_string())
            )
        },
        ExecuteMsg::Vote { poll_id, vote } => {
            let poll = POLLS.may_load(deps.storage, poll_id.clone())?;

            match poll {
                Some(mut poll) => {
                    BALLOTS.update(deps.storage, (info.sender.clone(), poll_id.clone()), |ballot| -> Result<Ballot, ContractError> {
                        match ballot {
                            Some(ballot) => {
                                // ballot already exists, must update vote counts
                                let position_of_old_vote = poll
                                    .options
                                    .iter()
                                    .position(|option| option.0 == ballot.option)
                                    .unwrap();
                                poll.options[position_of_old_vote].1 -= 1;
                                
                                Ok(Ballot {
                                    option: vote.clone(),
                                })
                            }
                            None => Ok(Ballot {
                                option: vote.clone(),
                            }),
                        }
                    })?;

                    // update the vote count
                    let position_of_new_vote = poll
                        .options
                        .iter()
                        .position(|option| option.0 == vote);
                    
                    match position_of_new_vote {
                        Some(position) => {
                            poll.options[position].1 += 1;
                        }
                        None => return Err(ContractError::VoteNotFound { poll_id, vote }),
                    }
                    POLLS.save(deps.storage, poll_id, &poll)?;

                    Ok(Response::new())
                }
                None => Err(ContractError::PollNotFound { poll_id }),
            }
        },
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetPoll { poll_id } => {
            let poll = POLLS.may_load(deps.storage, poll_id)?;
            Ok(to_json_binary(&poll)?)
        }
        QueryMsg::AllPolls {} => {
            let polls = POLLS
                .range(deps.storage, None, None, Order::Ascending)
                .map(|p| Ok(p?.1))
                .collect::<StdResult<Vec<_>>>()?;
            Ok(to_json_binary(&polls)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::{execute, instantiate, query};
    use crate::state::{Poll, POLLS};
    use cosmwasm_std::{attr, from_json, Addr}; // helper to construct an attribute e.g. ("action", "instantiate")
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env}; // mock functions to mock an environment, message info, dependencies
    use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg}; // our instantate method

    const ADDR1: &str = "wasm1pfq05em6sfkls66ut4m2257p7qwlk448h8mysz";
    const ADDR2: &str = "wasm1qzskhrcjnkdz2ln4yeafzsdwht8ch08j4wed69";

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let addr2: Addr = deps.api.addr_make(ADDR2);

        let msg = InstantiateMsg {
            admin: None,
        };
        let info = message_info(&addr2, &[]);
        let res = instantiate(deps.as_mut(), env, info, msg);

        match res {
            Ok(res) => {
                assert_eq!(res.messages.len(), 0);
                assert_eq!(res.attributes, vec![
                    attr("action", "instantiate"),
                    attr("admin", addr2.to_string()),
                ]);
            }
            Err(e) => {
                panic!("Test failed: {}", e);
            }
        }
    }

    #[test]
    fn test_instantiate_with_admin() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let addr1: Addr = deps.api.addr_make(ADDR1);

        let msg = InstantiateMsg {
            admin: Some(addr1.to_string()),
        };
        let info = message_info(&addr1, &[]);
        let res = instantiate(deps.as_mut(), env, info, msg);

        match res {
            Ok(res) => {
                assert_eq!(res.messages.len(), 0);
                assert_eq!(res.attributes, vec![
                    attr("action", "instantiate"),
                    attr("admin", addr1.to_string()),
                ]);
            }
            Err(e) => {
                panic!("Test failed: {}", e);
            }
        }
    }

    #[test]
    fn create_poll_valid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let addr1: Addr = deps.api.addr_make(ADDR1);

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "poll1".to_string(),
            question: "What is the best color?".to_string(),
            options: vec!["Red".to_string(), "Blue".to_string(), "Green".to_string()],
        };
        let info = message_info(&addr1, &[]);
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();
    }

    #[test]
    fn create_poll_invalid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let addr1: Addr = deps.api.addr_make(ADDR1);

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "poll1".to_string(),
            question: "What is the best color?".to_string(),
            options: vec![
                "Red".to_string(),
                "Blue".to_string(),
                "Green".to_string(),
                "Yellow".to_string(),
                "Black".to_string(),
                "White".to_string(),
                "Gray".to_string(),
                "Purple".to_string(),
                "Pink".to_string(),
                "Orange".to_string(),
                "Indigo".to_string(),
            ],
        };
        let info = message_info(&addr1, &[]);
        let _res = execute(deps.as_mut(), env, info, msg).unwrap_err();
    }

    #[test]
    fn vote_valid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let addr1: Addr = deps.api.addr_make(ADDR1);
        let addr2: Addr = deps.api.addr_make(ADDR2);

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "poll1".to_string(),
            question: "What is the best color?".to_string(),
            options: vec!["Red".to_string(), "Blue".to_string(), "Green".to_string()],
        };
        let info = message_info(&addr1, &[]);
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "poll1".to_string(),
            vote: "Red".to_string(),
        };
        let info = message_info(&addr1, &[]);

        let msg2 = ExecuteMsg::Vote {
            poll_id: "poll1".to_string(),
            vote: "Blue".to_string(),
        };
        let info2 = message_info(&addr2, &[]);
        
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        let _res = execute(deps.as_mut(), env.clone(), info2, msg2).unwrap();
        
        // Check that the storage value count of the corresponding poll vote is updated
        let poll: Option<Poll> = POLLS.may_load(deps.as_ref().storage, "poll1".to_string()).unwrap();
        match poll {
            Some(poll) => {
                let red_count = poll.options.iter().find(|(option, _)| option == "Red").map(|(_, count)| *count).unwrap();
                let blue_count = poll.options.iter().find(|(option, _)| option == "Blue").map(|(_, count)| *count).unwrap();
                let green_count = poll.options.iter().find(|(option, _)| option == "Green").map(|(_, count)| *count).unwrap();
                assert_eq!(red_count, 1, "Red vote count should be 1");
                assert_eq!(blue_count, 1, "Blue vote count should be 1");
                assert_eq!(green_count, 0, "Green vote count should be 0");
            }
            None => {
                panic!("Poll not found in storage");
            }
        }
    }

    #[test]
    fn vote_invalid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let addr1: Addr = deps.api.addr_make(ADDR1);

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "poll1".to_string(),
            question: "What is the best color?".to_string(),
            options: vec!["Red".to_string(), "Blue".to_string(), "Green".to_string()],
        };
        let info = message_info(&addr1, &[]);
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // vote for an invalid option
        let msg = ExecuteMsg::Vote {
            poll_id: "poll1".to_string(),
            vote: "Indigo".to_string(),
        };
        let info = message_info(&addr1, &[]);
        let _res = execute(deps.as_mut(), env, info, msg).unwrap_err();
    }

    #[test]
    fn vote_update_ballot() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let addr1: Addr = deps.api.addr_make(ADDR1);

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "poll1".to_string(),
            question: "What is the best color?".to_string(),
            options: vec!["Red".to_string(), "Blue".to_string(), "Green".to_string()],
        };
        let info = message_info(&addr1, &[]);
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "poll1".to_string(),
            vote: "Red".to_string(),
        };
        let info = message_info(&addr1, &[]);

        let msg2 = ExecuteMsg::Vote {
            poll_id: "poll1".to_string(),
            vote: "Blue".to_string(),
        };
        
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg2).unwrap();
        
        // Check that the storage value count of the corresponding poll vote is updated
        let poll: Option<Poll> = POLLS.may_load(deps.as_ref().storage, "poll1".to_string()).unwrap();
        match poll {
            Some(poll) => {
                let red_count = poll.options.iter().find(|(option, _)| option == "Red").map(|(_, count)| *count).unwrap();
                let blue_count = poll.options.iter().find(|(option, _)| option == "Blue").map(|(_, count)| *count).unwrap();
                let green_count = poll.options.iter().find(|(option, _)| option == "Green").map(|(_, count)| *count).unwrap();
                assert_eq!(red_count, 0, "Red vote count should be 1");
                assert_eq!(blue_count, 1, "Blue vote count should be 1");
                assert_eq!(green_count, 0, "Green vote count should be 0");
            }
            None => {
                panic!("Poll not found in storage");
            }
        }
    }
    
    #[test]
    fn query_get_poll() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let addr1: Addr = deps.api.addr_make(ADDR1);

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "poll1".to_string(),
            question: "What is the best color?".to_string(),
            options: vec!["Red".to_string(), "Blue".to_string(), "Green".to_string()],
        };
        let info = message_info(&addr1, &[]);
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = QueryMsg::GetPoll { poll_id: "poll1".to_string() };
        let res = query(deps.as_ref(), env, msg).unwrap();
        let poll: Option<Poll> = from_json(res).unwrap();
        assert_eq!(poll, Some(Poll {
            creator: addr1.clone(),
            question: "What is the best color?".to_string(),
            options: vec![("Red".to_string(), 0), ("Blue".to_string(), 0), ("Green".to_string(), 0)],
        }));
    }

    #[test]
    fn query_all_polls() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let addr1: Addr = deps.api.addr_make(ADDR1);

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "poll1".to_string(),
            question: "What is the best color?".to_string(),
            options: vec!["Red".to_string(), "Blue".to_string(), "Green".to_string()],
        };
        let info = message_info(&addr1, &[]);
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = QueryMsg::AllPolls {};
        let res = query(deps.as_ref(), env, msg).unwrap();
        let polls: Vec<Poll> = from_json(res).unwrap();
        assert_eq!(polls.len(), 1);
        assert_eq!(polls[0], Poll {
            creator: addr1.clone(),
            question: "What is the best color?".to_string(),
            options: vec![("Red".to_string(), 0), ("Blue".to_string(), 0), ("Green".to_string(), 0)],
        });
    }
}

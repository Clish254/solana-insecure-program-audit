# Solana insecure program audit
This is a report on the vulnerablities in this [insecure program](https://github.com/GitBolt/insecure-program) and how to fix them.
This is an assignment from module 5(solana program security) in the [solana summer fellowship](https://x.com/superteam/status/1811148171952721990).

As a short summary, below is a list of the issues that I have found:
* Missing signer checks in all instructions.
* Integer overflow/underflow in transfer_points instruction.
* Sender and receiver accounts in TransferPoints account struct are not set as mutable.
* Validation for duplicate mutable accounts is missing in transfer_points instruction.
* Invalid accounts struct passed to remove_user instruction
* Missing ownership check and close constraint in the remove user instruction.

These vulnerabilities are actually common pitfalls in solana smart contracts as mentioned in [this blog](https://neodyme.io/en/blog/solana_common_pitfalls/#intro)
by Neodyme which is one of the popular smart contract auditing firms on solana.

Now let's dive deep into these vulnarabilities and also look at how to fix them.

# Missing signer checks in all instructions.
Let's take a look at the **Account structs** for all three instructions.
The *Accounts struct* is where you define which accounts your instruction expects and which constraints these accounts should adhere to.

#### Initialize
```rust
#[instruction(id: u32)]
#[derive(Accounts)]
pub struct CreateUser<'info> {
    #[account(
        init,
        payer = signer,
        space = 8 + 4 + 32 + (4 + 10) + 2,
        seeds = [b"user", id.to_le_bytes().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,

    #[account(mut)]
    pub signer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}
```

#### Transfer points
```rust
#[instruction(id_sender: u32, id_receiver: u32)]
#[derive(Accounts)]
pub struct TransferPoints<'info> {
    #[account(
        seeds = [b"user", id_sender.to_le_bytes().as_ref()],
        bump
    )]
    pub sender: Account<'info, User>,
    #[account(
        seeds = [b"user", id_receiver.to_le_bytes().as_ref()],
        bump
    )]
    pub receiver: Account<'info, User>,
    #[account(mut)]
    pub signer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}
```

#### Remove user
```rust
#[instruction(id: u32)]
#[derive(Accounts)]
pub struct RemoveUser<'info> {
    #[account(
        seeds = [b"user", id.to_le_bytes().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,
    #[account(mut)]
    pub signer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}
```

All three account structs have a `signer` field, but it's of type `AccountInfo<'info>` which can be any account.
So any account can be passed as the `signer` which is not ideal because e.g in the **initialize instruction** there is this line of code:
```rust
user.owner = *ctx.accounts.signer.key;
```
This line means that we want to set the signer as the owner of the initialized user account.
But without the signer check we are not sure the account passed as the signer is the actual signer of the instruction.

In the **TransferPoints** accounts struct there is also no signer check meaning any user can transfer points from any sender account to any receiver account.
There is no check to make sure the sender is the signer of the transaction.

In the **RemoveUser** accounts struct there is also no signer check meaning anyone can close any user's account.

We can fix these issues by updating the signer field in all account structs to use the **Signer** type in the instruction context in anchor:
```rust
pub signer: Signer<'info>
```
This will verify that the account is actually the signer of the transaction.

# Integer overflow/underflow in transfer_points instruction.
Rust does not always catch onverflows. It only catches overflows in debug mode. In release mode i.e when you do `cargo build-bpf` it does not check for overflows.
If an arithmetic operation results in a higher value or lower value than what is supported by the integer type e.g `u8`, the value will wrap around with [two's complement](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow).

In the **transfer_points** instruction we have these two lines of code:
```rust
sender.points -= amount;
receiver.points += amount;
```
The type for `amount` and user `points` is `u16`, which can hold values from 0 to 65,535.
1. Integer Underflow: This can happen in the `sender.points -= amount;` operation. If `sender.points` is less than `amount`, Rust's default behavior in debug builds is to panic (crash the program). In release builds, the operation wraps around. Example:
    - If `sender.points` is 1000 and `amount` is 1001, the result would be 65,535 in release mode (wrapping behavior).
    - 1000 - 1001 = -1, but since it's unsigned, it wraps to 65,535 (2^16 - 1).
2. Integer Overflow: This can occur in the `receiver.points += amount;` operation. If the sum of `receiver.points` and `amount` exceeds 65,535, it will also wrap around in release builds. Example:
    - If `receiver.points` is 65,000 and `amount` is 1000, the result would be 464 in release mode.
    - 65,000 + 1000 = 66,000, but this exceeds the maximum value of u16, so it wraps to 66,000 - 65,536 = 464.
To fix this we can use checked arithmetic operations as shown below:
```rust
sender.points = sender
   .points
   .checked_sub(amount)
   .ok_or(MyError::IntegerUnderflow)?;
receiver.points = receiver
   .points
   .checked_add(amount)
   .ok_or(MyError::IntegerOverflow)?;

// update the error enum to be as follows:
#[error_code]
pub enum MyError {
    #[msg("Not enough points to transfer")]
    NotEnoughPoints,
    #[msg("Integer overflow")]
    IntegerOverflow,
    #[msg("Integer underflow")]
    IntegerUnderflow,
}
```

# Sender and receiver accounts in TransferPoints account struct are not set as mutable.
To be able to transfer points from the sender to the receiver the two accounts should be defined as mutable.
However, `sender` and `receiver` accounts in `TransferPoints` account struct looks like this.
```rust
#[instruction(id_sender: u32, id_receiver: u32)]
#[derive(Accounts)]
pub struct TransferPoints<'info> {
    #[account(
        seeds = [b"user", id_sender.to_le_bytes().as_ref()],
        bump
    )]
    pub sender: Account<'info, User>,
    #[account(
        seeds = [b"user", id_receiver.to_le_bytes().as_ref()],
        bump
    )]
    pub receiver: Account<'info, User>,
    #[account(mut)]
    pub signer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}
```
The two accounts do not have the `mut` constraint which is used to indicate that an account should be mutable.
To fix this we can update the `TransferPoints` accounts struct as follows:
```rust
#[instruction(id_sender: u32, id_receiver: u32)]
#[derive(Accounts)]
pub struct TransferPoints<'info> {
    #[account(
        mut,
        seeds = [b"user", id_sender.to_le_bytes().as_ref()],
        bump
    )]
    pub sender: Account<'info, User>,
    #[account(
        mut,
        seeds = [b"user", id_receiver.to_le_bytes().as_ref()],
        bump
    )]
    pub receiver: Account<'info, User>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

# Validation for duplicate mutable accounts is missing in transfer_points instruction.
We have updated the `TransferPoints` accounts struct to include the `mut` constraint which indicates that `sender` and `receiver` accounts should be mutable.
But there is one more thing that is missing, there is no check in the transfer_points instruction to make sure the sender and receiver accounts are **different**.

So the logic below can make changes to the same account which is not what we want:
```rust
sender.points -= amount;
receiver.points += amount;
```
To fix this we need to add a check to make sure the provided sender account is different from the provided receiver account.
We can do this by making sure the `id_sender` and `id_receiver` accounts are different.

# Invalid accounts struct passed to remove_user instruction.
The remove_user instruction is using the `TransferPoints` accounts struct instead of `RemoveUser`. This is definitely not what we want. To fix this, use the RemoveUser accounts struct as shown below
```rust
pub fn remove_user(_ctx: Context<RemoveUser>, id:u32) -> Result<()> {
  msg!("Account closed for user with id: {}", id);
  Ok(())
}
```
# Missing ownership check and close constraint in the remove user instruction.
The first pitfal we covered was missing signer checks in all the account structs and we fixed that by adding the Signer type to the signer account as follows:
```rust
pub signer: Signer<'info>
```
Next in the `remove_user` instruction we need to add **ownership checks**, this is because we need to make sure the person closing the user account is actually the owner of the account.
Without this any person can call this instruction and close any user's account.
We also need to add the anchor `close` constraint to securely close the account. As it is the code does not actually close the account

Below is the fixed code example:
```rust
#[instruction(id: u32)]
#[derive(Accounts)]
pub struct RemoveUser<'info> {
    #[account(
        mut,
        close = signer,
        seeds = [b"user", id.to_le_bytes().as_ref()],
        bump,
        constraint = user.owner == signer.key()
    )]
    pub user: Account<'info, User>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```
With the above code the account will be closed and only the account's owner can close it as the signer of the transaction.

So these are some of the issues I have found in [this](https://github.com/GitBolt/insecure-program) program.

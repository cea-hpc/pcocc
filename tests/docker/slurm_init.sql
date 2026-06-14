CREATE database slurm_acct_db;
CREATE user 'slurm'@'localhost';
GRANT ALL ON slurm_acct_db.* TO 'slurm'@'localhost';

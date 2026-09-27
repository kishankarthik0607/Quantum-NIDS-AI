"""
Data Preprocessing Module for NIDS-ML

This module handles:
- Loading CICIDS 2017 / NSL-KDD dataset
- Data cleaning (handling missing values, duplicates, infinite values)
- Encoding categorical features (Label encoding, One-hot encoding)
- Feature normalization/standardization (StandardScaler, MinMaxScaler)
- Handling class imbalance using SMOTE (Synthetic Minority Over-sampling Technique)
- Train-test splitting with stratification

Author: Priyanshu Kumar
Date: November 10, 2025
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from imblearn.over_sampling import SMOTE
import logging
import os
import glob
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Configure logging
log_dir = Path(__file__).parent.parent / 'logs'
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'preprocessing.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Fix Windows console encoding
import sys
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

logger = logging.getLogger(__name__)


def load_dataset(data_dir='../data/raw'):
    """
    Load CIC-IDS2017 CSV files using memory-safe chunked sampling.

    Instead of loading all ~2.8M rows into RAM, this function reads
    each CSV in chunks and keeps a controlled number of rows.

    Returns:
        pd.DataFrame: Memory-manageable merged dataset
    """
    logger.info("=" * 60)
    logger.info("STEP 1: LOADING DATASET")
    logger.info("=" * 60)

    # ---------------------------------------------------------
    # MEMORY-SAFE SETTINGS
    # ---------------------------------------------------------
    CHUNK_SIZE = 50_000

    # Maximum rows retained from each CSV.
    # 100,000 x 8 files = approximately 800,000 rows maximum.
    MAX_ROWS_PER_FILE = 25_000

    # ---------------------------------------------------------
    # DATA DIRECTORY
    # ---------------------------------------------------------
    data_path = Path(__file__).parent.parent / 'data' / 'raw'

    if not data_path.exists():
        logger.error(f"Data directory not found: {data_path}")
        raise FileNotFoundError(
            f"Please place dataset files in {data_path}"
        )

    # ---------------------------------------------------------
    # FIND CSV FILES
    # ---------------------------------------------------------
    csv_files = sorted(data_path.glob('*.csv'))

    if not csv_files:
        logger.error(f"No CSV files found in {data_path}")
        raise FileNotFoundError(
            f"Please place CSV dataset files in {data_path}"
        )

    logger.info(f"Found {len(csv_files)} CSV file(s) in {data_path}")

    # ---------------------------------------------------------
    # LOAD EACH FILE IN CHUNKS
    # ---------------------------------------------------------
    dataframes = []

    for csv_file in csv_files:

        logger.info(f"Loading: {csv_file.name}")

        file_chunks = []
        rows_collected = 0

        try:

            reader = pd.read_csv(
                csv_file,
                encoding='utf-8',
                low_memory=True,
                chunksize=CHUNK_SIZE
            )

            for chunk_number, chunk in enumerate(reader, start=1):

                # Remove completely empty rows
                chunk = chunk.dropna(how='all')

                if chunk.empty:
                    continue

                # -------------------------------------------------
                # RANDOMLY SAMPLE FROM EACH CHUNK
                # -------------------------------------------------
                remaining = MAX_ROWS_PER_FILE - rows_collected

                if remaining <= 0:
                    break

                if len(chunk) > remaining:
                    chunk = chunk.sample(
                        n=remaining,
                        random_state=42
                    )

                file_chunks.append(chunk)
                rows_collected += len(chunk)

                logger.info(
                    f"  Chunk {chunk_number}: "
                    f"collected {rows_collected:,}/"
                    f"{MAX_ROWS_PER_FILE:,} rows"
                )

                if rows_collected >= MAX_ROWS_PER_FILE:
                    break

            if file_chunks:

                file_df = pd.concat(
                    file_chunks,
                    ignore_index=True
                )

                dataframes.append(file_df)

                logger.info(
                    f"  ✓ Loaded {len(file_df):,} rows, "
                    f"{len(file_df.columns)} columns"
                )

                # Release temporary chunk memory
                del file_chunks
                del file_df

            else:
                logger.warning(
                    f"  ✗ No usable rows found in {csv_file.name}"
                )

        except Exception as e:

            logger.warning(
                f"  ✗ Failed to load {csv_file.name}: {str(e)}"
            )

            continue

    # ---------------------------------------------------------
    # VERIFY DATA
    # ---------------------------------------------------------
    if not dataframes:
        raise ValueError(
            "No data could be loaded from CSV files"
        )

    # ---------------------------------------------------------
    # MERGE CONTROLLED DATASET
    # ---------------------------------------------------------
    logger.info("Merging sampled datasets...")

    df_raw = pd.concat(
        dataframes,
        ignore_index=True
    )

    # Release list of individual DataFrames
    del dataframes

    # ---------------------------------------------------------
    # DATASET SUMMARY
    # ---------------------------------------------------------
    logger.info("\n" + "-" * 60)
    logger.info("DATASET SUMMARY")
    logger.info("-" * 60)

    logger.info(
        f"Total Rows: {len(df_raw):,}"
    )

    logger.info(
        f"Total Columns: {len(df_raw.columns)}"
    )

    logger.info(
        f"Memory Usage: "
        f"{df_raw.memory_usage(deep=True).sum() / 1024**2:.2f} MB"
    )

    # ---------------------------------------------------------
    # DUPLICATES
    # ---------------------------------------------------------
    try:

        duplicate_count = df_raw.duplicated().sum()

        logger.info(
            f"Duplicate Rows: {duplicate_count:,}"
        )

    except Exception as e:

        logger.warning(
            f"Could not calculate duplicates: {e}"
        )

    # ---------------------------------------------------------
    # MISSING VALUES
    # ---------------------------------------------------------
    missing_values = df_raw.isnull().sum()

    missing_count = (missing_values > 0).sum()

    logger.info(
        f"Columns with Missing Values: {missing_count}"
    )

    if missing_count > 0:

        logger.info(
            "\nMissing Values per Column:"
        )

        for col, count in missing_values[
            missing_values > 0
        ].items():

            percentage = (
                count / len(df_raw)
            ) * 100

            logger.info(
                f"  {col}: "
                f"{count:,} "
                f"({percentage:.2f}%)"
            )

    logger.info("-" * 60 + "\n")

    return df_raw


def handle_missing_values(df, threshold=0.3):
    """
    Handle missing values in the dataset:
    - Drop columns with > threshold missing data
    - Replace numeric missing values with median
    - Replace categorical missing values with mode
    
    Args:
        df (pd.DataFrame): Input dataset
        threshold (float): Threshold for dropping columns (default: 0.3 = 30%)
        
    Returns:
        pd.DataFrame: Dataset with handled missing values
    """
    logger.info("="*60)
    logger.info("STEP 2: HANDLING MISSING VALUES")
    logger.info("="*60)
    
    df_clean = df.copy()
    initial_cols = len(df_clean.columns)
    
    # Calculate missing percentage for each column
    missing_percentages = df_clean.isnull().sum() / len(df_clean)
    
    # Drop columns with > threshold missing data
    cols_to_drop = missing_percentages[missing_percentages > threshold].index.tolist()
    
    if cols_to_drop:
        logger.info(f"Dropping {len(cols_to_drop)} columns with >{threshold*100}% missing data:")
        for col in cols_to_drop:
            percentage = missing_percentages[col] * 100
            logger.info(f"  - {col}: {percentage:.2f}% missing")
        df_clean.drop(columns=cols_to_drop, inplace=True)
    else:
        logger.info(f"No columns exceed {threshold*100}% missing data threshold")
    
    # Handle remaining missing values
    numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
    categorical_cols = df_clean.select_dtypes(include=['object']).columns
    
    # Replace numeric missing values with median
    for col in numeric_cols:
        if df_clean[col].isnull().any():
            median_value = df_clean[col].median()
            missing_count = df_clean[col].isnull().sum()
            df_clean[col].fillna(median_value, inplace=True)
            logger.info(f"Replaced {missing_count:,} missing values in '{col}' with median: {median_value:.2f}")
    
    # Replace categorical missing values with mode
    for col in categorical_cols:
        if df_clean[col].isnull().any():
            mode_value = df_clean[col].mode()[0] if not df_clean[col].mode().empty else 'Unknown'
            missing_count = df_clean[col].isnull().sum()
            df_clean[col].fillna(mode_value, inplace=True)
            logger.info(f"Replaced {missing_count:,} missing values in '{col}' with mode: '{mode_value}'")
    
    # Handle infinite values in numeric columns
    logger.info("\nHandling infinite values...")
    inf_count = 0
    for col in numeric_cols:
        inf_mask = np.isinf(df_clean[col])
        if inf_mask.any():
            count = inf_mask.sum()
            inf_count += count
            # Replace inf with max/min finite values
            finite_vals = df_clean[col][~inf_mask]
            if len(finite_vals) > 0:
                df_clean.loc[inf_mask & (df_clean[col] > 0), col] = finite_vals.max()
                df_clean.loc[inf_mask & (df_clean[col] < 0), col] = finite_vals.min()
            else:
                df_clean.loc[inf_mask, col] = 0
            logger.info(f"  Replaced {count:,} infinite values in '{col}'")
    
    if inf_count == 0:
        logger.info("  No infinite values found")
    
    logger.info(f"\nColumns after cleaning: {len(df_clean.columns)} (dropped {initial_cols - len(df_clean.columns)})")
    logger.info("-"*60 + "\n")
    
    return df_clean


def encode_and_label(df):
    """
    Encode categorical features and standardize labels.
    - Encode categorical columns using LabelEncoder
    - Standardize label: BENIGN/normal → 0, attacks → 1
    - Separate features (X) and labels (y)
    
    Args:
        df (pd.DataFrame): Cleaned dataset
        
    Returns:
        tuple: (X, y, label_column_name)
    """
    logger.info("="*60)
    logger.info("STEP 3: ENCODING AND LABEL SEPARATION")
    logger.info("="*60)
    
    df_encoded = df.copy()
    
    # Clean column names (remove spaces and special characters)
    df_encoded.columns = df_encoded.columns.str.strip().str.replace(' ', '_')
    logger.info(f"Cleaned column names")
    
    # Identify label column (common names in CICIDS 2017 and NSL-KDD)
    label_candidates = ['Label', 'label', 'class', 'Class', 'attack', 'Attack']
    label_col = None
    
    for candidate in label_candidates:
        if candidate in df_encoded.columns:
            label_col = candidate
            break
    
    if label_col is None:
        # Try to find column with 'label' or 'class' in name
        for col in df_encoded.columns:
            if 'label' in col.lower() or 'class' in col.lower():
                label_col = col
                break
    
    if label_col is None:
        logger.error("Could not identify label column. Please ensure dataset has 'Label' or 'Class' column")
        raise ValueError("Label column not found in dataset")
    
    logger.info(f"Identified label column: '{label_col}'")

    # Remove rows with missing labels
    missing_labels = df_encoded[label_col].isna().sum()

    if missing_labels > 0:
        logger.warning(
            f"Removing {missing_labels:,} rows with missing labels"
        )
        df_encoded = df_encoded.dropna(
            subset=[label_col]
        ).reset_index(drop=True)
    
    # Display label distribution before encoding
    logger.info(f"\nOriginal Label Distribution:")
    label_counts = df_encoded[label_col].value_counts()
    for label, count in label_counts.items():
        percentage = (count / len(df_encoded)) * 100
        logger.info(f"  {label}: {count:,} ({percentage:.2f}%)")
    
    # Standardize labels to binary (0 = BENIGN, 1 = ATTACK)
    benign_variants = ['BENIGN', 'benign', 'normal', 'Normal', 'NORMAL']
    df_encoded['Binary_Label'] = df_encoded[label_col].apply(
        lambda x: 0 if str(x).strip() in benign_variants else 1
    )
    
    # Keep original label for multi-class classification later
    df_encoded['Original_Label'] = df_encoded[label_col]
    
    # Separate features and labels
    y = df_encoded['Binary_Label']
    original_labels = df_encoded['Original_Label']
    
    # Drop label columns from features
    X = df_encoded.drop(columns=[label_col, 'Binary_Label', 'Original_Label'])
    
    logger.info(f"\nBinary Label Distribution:")
    logger.info(f"  BENIGN (0): {(y == 0).sum():,} ({(y == 0).sum() / len(y) * 100:.2f}%)")
    logger.info(f"  ATTACK (1): {(y == 1).sum():,} ({(y == 1).sum() / len(y) * 100:.2f}%)")
    
    # Encode categorical features
    categorical_cols = X.select_dtypes(include=['object']).columns.tolist()
    
    if categorical_cols:
        logger.info(f"\nEncoding {len(categorical_cols)} categorical columns:")
        for col in categorical_cols:
            unique_count = X[col].nunique()
            logger.info(f"  - {col}: {unique_count} unique values")
            
            # Use LabelEncoder for columns with many categories
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
    else:
        logger.info("\nNo categorical columns found to encode")
    
    logger.info(f"\nFeature Matrix (X): {X.shape}")
    logger.info(f"Label Vector (y): {y.shape}")
    logger.info("-"*60 + "\n")
    
    return X, y, label_col


def normalize_features(X):
    """
    Normalize numeric features using StandardScaler (zero mean, unit variance).
    
    Args:
        X (pd.DataFrame): Feature matrix
        
    Returns:
        tuple: (X_normalized, scaler)
    """
    logger.info("="*60)
    logger.info("STEP 4: FEATURE NORMALIZATION")
    logger.info("="*60)
    
    # Display statistics before normalization
    logger.info("Sample statistics BEFORE normalization:")
    sample_cols = X.columns[:3].tolist()  # First 3 columns
    for col in sample_cols:
        logger.info(f"  {col}: mean={X[col].mean():.4f}, std={X[col].std():.4f}")
    
    # Apply StandardScaler
    scaler = StandardScaler()
    X_normalized = scaler.fit_transform(X)
    
    # Convert back to DataFrame to preserve column names
    X_normalized = pd.DataFrame(X_normalized, columns=X.columns)

    # Check for NaN values after normalization
    nan_counts = X_normalized.isna().sum()
    total_nan = nan_counts.sum()

    if total_nan > 0:
        logger.warning(f"NaN values remaining after normalization: {total_nan:,}")

        for col, count in nan_counts[nan_counts > 0].items():
            logger.warning(f"  {col}: {count:,} NaN values")

        # Replace remaining NaN values with 0
        X_normalized = X_normalized.fillna(0)

        logger.info("✓ Remaining NaN values replaced with 0")
    else:
        logger.info("✓ No NaN values found after normalization")
    
    # Display statistics after normalization
    logger.info("\nSample statistics AFTER normalization:")
    for col in sample_cols:
        logger.info(f"  {col}: mean={X_normalized[col].mean():.4f}, std={X_normalized[col].std():.4f}")
    
    logger.info(f"\nNormalized feature matrix shape: {X_normalized.shape}")
    logger.info("-"*60 + "\n")
    
    return X_normalized, scaler
def apply_smote(X, y, random_state=42):
    """
    Apply memory-safe SMOTE to a controlled training subset.
    """

    logger.info("=" * 60)
    logger.info("STEP 5: CLASS BALANCING WITH MEMORY-SAFE SMOTE")
    logger.info("=" * 60)

    # Convert labels to numpy array
    y_array = np.asarray(y)

    unique, counts = np.unique(y_array, return_counts=True)

    logger.info("Class distribution BEFORE SMOTE:")

    for label, count in zip(unique, counts):
        percentage = (count / len(y_array)) * 100
        label_name = "BENIGN" if label == 0 else "ATTACK"
        logger.info(
            f"  {label_name} ({label}): "
            f"{count:,} ({percentage:.2f}%)"
        )

    # ---------------------------------------------------------
    # MEMORY-SAFE SUBSAMPLING
    # ---------------------------------------------------------

    MAX_SAMPLES_PER_CLASS = 30_000

    rng = np.random.RandomState(random_state)

    benign_indices = np.where(y_array == 0)[0]
    attack_indices = np.where(y_array == 1)[0]

    # Keep at most 30,000 samples from each class
    benign_sample_size = min(
        MAX_SAMPLES_PER_CLASS,
        len(benign_indices)
    )

    attack_sample_size = min(
        MAX_SAMPLES_PER_CLASS,
        len(attack_indices)
    )

    benign_indices = rng.choice(
        benign_indices,
        size=benign_sample_size,
        replace=False
    )

    attack_indices = rng.choice(
        attack_indices,
        size=attack_sample_size,
        replace=False
    )

    selected_indices = np.concatenate([
        benign_indices,
        attack_indices
    ])

    rng.shuffle(selected_indices)

    X_sample = X.iloc[selected_indices].copy()
    y_sample = y.iloc[selected_indices].copy()

    logger.info("")
    logger.info("Memory-safe SMOTE subset:")
    logger.info(f"  BENIGN samples: {benign_sample_size:,}")
    logger.info(f"  ATTACK samples: {attack_sample_size:,}")
    logger.info(
        f"  Total samples used for SMOTE: "
        f"{len(selected_indices):,}"
    )

    # ---------------------------------------------------------
    # APPLY SMOTE
    # ---------------------------------------------------------

    sample_unique, sample_counts = np.unique(
        y_sample,
        return_counts=True
    )

    majority_count = sample_counts.max()
    minority_count = sample_counts.min()

    # Balance minority class to match majority class
    target_minority = majority_count

    logger.info("")
    logger.info("Applying SMOTE to controlled subset...")
    logger.info(
        f"Target minority samples: "
        f"{target_minority:,}"
    )

    try:

        smote = SMOTE(
            sampling_strategy={
                1: target_minority
            },
            random_state=random_state,
            k_neighbors=5
        )

        X_balanced, y_balanced = smote.fit_resample(
            X_sample,
            y_sample
        )

        logger.info("")
        logger.info("Class distribution AFTER SMOTE:")

        unique_after, counts_after = np.unique(
            y_balanced,
            return_counts=True
        )

        for label, count in zip(
            unique_after,
            counts_after
        ):
            percentage = (
                count / len(y_balanced)
            ) * 100

            label_name = (
                "BENIGN"
                if label == 0
                else "ATTACK"
            )

            logger.info(
                f"  {label_name} ({label}): "
                f"{count:,} "
                f"({percentage:.2f}%)"
            )

        logger.info(
            f"\nBalanced dataset shape: "
            f"{X_balanced.shape}"
        )

        return X_balanced, y_balanced

    except Exception as e:

        logger.warning(
            f"SMOTE failed: {str(e)}"
        )

        logger.warning(
            "Proceeding with sampled data without SMOTE."
        )

        return X_sample, y_sample


def save_processed_data(X, y, output_dir='../data/processed'):
    """
    Save preprocessed data to CSV using chunked writing
    to reduce RAM usage on Windows.
    """
    logger.info("=" * 60)
    logger.info("STEP 6: SAVING PROCESSED DATA")
    logger.info("=" * 60)

    output_path = Path(__file__).parent.parent / 'data' / 'processed'
    output_path.mkdir(parents=True, exist_ok=True)

    output_file = output_path / 'cleaned_data.csv'

    # Remove old file if it exists
    if output_file.exists():
        output_file.unlink()

    logger.info(f"Saving {len(X):,} rows in chunks...")

    chunk_size = 25_000

    for start in range(0, len(X), chunk_size):
        end = min(start + chunk_size, len(X))

        # Create only one small chunk in memory
        chunk = X.iloc[start:end].copy()
        chunk['Label'] = y.iloc[start:end].values

        # Write header only for the first chunk
        chunk.to_csv(
            output_file,
            mode='w' if start == 0 else 'a',
            header=(start == 0),
            index=False
        )

        del chunk

        logger.info(
            f"  Saved rows {start + 1:,} - {end:,} "
            f"of {len(X):,}"
        )

    file_size = output_file.stat().st_size / 1024**2

    logger.info(f"✓ Saved processed data to: {output_file}")
    logger.info(f"  Rows: {len(X):,}")
    logger.info(f"  Columns: {len(X.columns) + 1} "
                f"({len(X.columns)} features + 1 label)")
    logger.info(f"  File size: {file_size:.2f} MB")
    logger.info("-" * 60 + "\n")

    return output_file

def main():
    """
    Main function to execute the complete preprocessing pipeline.
    """
    try:
        logger.info("\n" + "="*60)
        logger.info("NIDS-ML DATA PREPROCESSING PIPELINE")
        logger.info("="*60 + "\n")
        
        # Step 1: Load dataset
        df_raw = load_dataset()
        
        # Step 2: Handle missing values
        df_clean = handle_missing_values(df_raw, threshold=0.3)
        
        # Remove duplicates
        logger.info("Removing duplicate rows...")
        duplicates = df_clean.duplicated().sum()
        if duplicates > 0:
            df_clean = df_clean.drop_duplicates()
            logger.info(f"Removed {duplicates:,} duplicate rows\n")
        else:
            logger.info("No duplicate rows found\n")
        
        # Step 3: Encode and separate features/labels
        X, y, label_col = encode_and_label(df_clean)
        
        # Step 4: Normalize features
        X_normalized, scaler = normalize_features(X)
        
        # Step 5: Apply SMOTE for class balancing
        X_balanced, y_balanced = apply_smote(X_normalized, y, random_state=42)
        
        # Step 6: Save processed data
        output_file = save_processed_data(X_balanced, y_balanced)
        
        # Final summary
        logger.info("="*60)
        logger.info("PREPROCESSING COMPLETED SUCCESSFULLY! ✓")
        logger.info("="*60)
        logger.info(f"Final Dataset Shape: {X_balanced.shape[0]:,} rows × {X_balanced.shape[1]} features")
        logger.info(f"Output File: {output_file}")
        logger.info(f"Next Step: Feature Selection (Part 3)")
        logger.info("="*60 + "\n")
        
        return X_balanced, y_balanced, scaler
        
    except Exception as e:
        logger.error(f"Preprocessing failed: {str(e)}", exc_info=True)
        raise



class DataPreprocessor:
    """
    Object-oriented wrapper for data preprocessing operations.
    Provides a convenient interface for the preprocessing pipeline.
    """
    
    def __init__(self, data_dir='../data/raw'):
        """
        Initialize the preprocessor.
        
        Args:
            data_dir (str): Path to the raw dataset directory
        """
        self.data_dir = data_dir
        self.df = None
        self.X = None
        self.y = None
        self.X_balanced = None
        self.y_balanced = None
        self.scaler = None
        self.label_col = None
        
    def preprocess_pipeline(self, apply_balancing=True, random_state=42):
        """
        Execute complete preprocessing pipeline.
        
        Args:
            apply_balancing (bool): Whether to apply SMOTE balancing
            random_state (int): Random seed for reproducibility
            
        Returns:
            tuple: Preprocessed X_balanced, y_balanced, scaler
        """
        # Load dataset
        self.df = load_dataset(self.data_dir)
        
        # Handle missing values
        df_clean = handle_missing_values(self.df, threshold=0.3)
        
        # Remove duplicates
        logger.info("Removing duplicate rows...")
        duplicates = df_clean.duplicated().sum()
        if duplicates > 0:
            df_clean = df_clean.drop_duplicates()
            logger.info(f"Removed {duplicates:,} duplicate rows\n")
        
        # Encode and separate features/labels
        self.X, self.y, self.label_col = encode_and_label(df_clean)
        
        # Normalize features
        X_normalized, self.scaler = normalize_features(self.X)
        
        # Apply SMOTE if requested
        if apply_balancing:
            self.X_balanced, self.y_balanced = apply_smote(X_normalized, self.y, random_state)
        else:
            self.X_balanced, self.y_balanced = X_normalized, self.y
        
        return self.X_balanced, self.y_balanced, self.scaler
    
    def save_data(self, output_dir='../data/processed'):
        """
        Save preprocessed data to disk.
        
        Args:
            output_dir (str): Directory to save processed data
            
        Returns:
            Path: Path to saved file
        """
        if self.X_balanced is None or self.y_balanced is None:
            raise ValueError("No preprocessed data to save. Run preprocess_pipeline() first.")
        
        return save_processed_data(self.X_balanced, self.y_balanced, output_dir)


if __name__ == "__main__":
    """
    Execute preprocessing pipeline when run as main script.
    """
    main()



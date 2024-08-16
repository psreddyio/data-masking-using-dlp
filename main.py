from typing import Dict, List, Union

import google.cloud.dlp
from google.cloud import bigquery
import pandas as pd
import os
import argparse


def deidentify_table_replace_with_info_types(
    project: str,
    dataset: str,
    input_table: str,
    output_table: str,
    chunksize: str,
    # table_data: Dict[str, Union[List[str], List[List[str]]]],
    info_types: List[str],
    deid_content_list: List[str],
) -> None:
    """ Uses the Data Loss Prevention API to de-identify sensitive data in a
      table by replacing them with info type.

    Args:
        project: The Google Cloud project id to use as a parent resource.
        table_data: Json string representing table data.
        info_types: A list of strings representing info types to look for.
            A full list of info type categories can be fetched from the API.
        deid_content_list: A list of fields in table to de-identify

    Returns:
        None; the response from the API is printed to the terminal.

    Example:
    >> $ python deidentify_table_infotypes.py \
    '{
        "header": ["name", "email", "phone number"],
        "rows": [
            ["Robert Frost", "robertfrost@example.com", "4232342345"],
            ["John Doe", "johndoe@example.com", "4253458383"]
        ]
    }' \
    ["PERSON_NAME"] ["name"]
    >> '{
            "header": ["name", "email", "phone number"],
            "rows": [
                ["[PERSON_NAME]", "robertfrost@example.com", "4232342345"],
                ["[PERSON_NAME]", "johndoe@example.com", "4253458383"]
            ]
        }'
    """

    # Instantiate a client.
    dlp = google.cloud.dlp_v2.DlpServiceClient()
    bq_client = bigquery.Client()

    # Fetch data from BigQuery
    query = f"""
        SELECT *
        FROM `{project}.{dataset}.{input_table}` 
    """

    table_id = "project_id.dataset_id.table_id"

    job_config = bigquery.QueryJobConfig(
        allow_large_results=True,
        destination=table_id,
        write_disposition="WRITE_TRUNCATE",
    )

    query_job = bq_client.query(query, job_config=job_config)  # API request
    query_job.result()  # Waits for query to finish
    print("Response too large table completed")

    rows_iter = bq_client.list_rows(table_id)

    # Construct the `table`. For more details on the table schema, please see
    # https://cloud.google.com/dlp/docs/reference/rest/v2/ContentItem#Table
    headers = [{"name": column.name} for column in rows_iter.schema]
    rows_data = []
    for row in rows_iter:
        rows_data.append(
            {"values": [{"string_value": str(cell_val)} for cell_val in row]}
        )

    table = {"headers": headers, "rows": rows_data}

    # Construct item
    item = {"table": table}

    # Specify fields to be de-identified
    deid_content_list = [{"name": _i} for _i in deid_content_list]

    # Construct inspect configuration dictionary
    inspect_config = {"info_types": [{"name": info_type} for info_type in info_types]}

    # Construct deidentify configuration dictionary
    deidentify_config = {
        "record_transformations": {
            "field_transformations": [
                {
                    "info_type_transformations": {
                        "transformations": [
                            {
                                "primitive_transformation": {
                                    "replace_config": {
                                        "new_value": {
                                            "string_value": "################"
                                        }
                                    }
                                }
                            }
                        ]
                    },
                    "fields": deid_content_list,
                }
            ]
        }
    }

    # Convert the project id into a full resource id.
    parent = f"projects/{project}/locations/global"

    # Call the API.
    response = dlp.deidentify_content(
        request={
            "parent": parent,
            "deidentify_config": {
                "deidentify_template_name": "projects/project_id/locations/global/deidentifyTemplates/template_id",
            },
            "item": item,
            "inspect_config": inspect_config,
        }
    )

    # Print the result
    # print(f"Table after de-identification: {response.item.table}")

    # Convert the de-identified table to a pandas DataFrame
    deid_data = []
    chunk_size = int(chunksize)  # Adjust this value based on your available memory
    num_chunks = len(response.item.table.rows) // chunk_size
    print(f"num_chunks: {num_chunks}")
    for i in range(num_chunks + 1):
        start_index = i * chunk_size
        end_index = start_index + chunk_size
        chunk = response.item.table.rows[start_index:end_index]

        for row in chunk:
            deid_data.append([cell.string_value for cell in row.values])

        # if deid_data:
        chunk_df = pd.DataFrame(
            deid_data,
            columns=[header.name for header in response.item.table.headers],
        )
        # Write the DataFrame back to BigQuery
        table_id = f"{project}.{dataset}.{output_table}"
        job_config = bigquery.LoadJobConfig(write_disposition="WRITE_TRUNCATE")
        job = bq_client.load_table_from_dataframe(
            chunk_df,
            table_id,
            # job_config=job_config
        )
        job.result()  # Waits for the job to complete
        deid_data = []
        print(f"Loaded chunk to {table_id}")

    print(f"full load comepleted for {table_id}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", help="GCP Project")
    parser.add_argument("--dataset", help="GCP Dataset")
    parser.add_argument("--input_table", help="input_table")
    parser.add_argument("--output_table", help="masked table")
    parser.add_argument("--chunksize", help="chunksize")
    # parser.add_argument("--info_types", help="info_types")

    args = parser.parse_args()

    project = args.project
    dataset = args.dataset
    input_table = args.input_table
    output_table = args.output_table
    chunksize = args.chunksize
    # info_types = args.info_types

    deidentify_table_replace_with_info_types(
        project,
        dataset,
        input_table,
        output_table,
        chunksize,
        [
            "ARGENTINA_DNI_NUMBER",
            "AUSTRALIA_DRIVERS_LICENSE_NUMBER",
            "AUSTRALIA_MEDICARE_NUMBER",
            "AUSTRALIA_PASSPORT",
            "AUSTRALIA_TAX_FILE_NUMBER",
            "AUTH_TOKEN",
            "AWS_CREDENTIALS",
            "AZERBAIJAN_PASSPORT",
            "AZURE_AUTH_TOKEN",
            "BELARUS_PASSPORT",
            "BELGIUM_NATIONAL_ID_CARD_NUMBER",
            "BRAZIL_CPF_NUMBER",
            "CANADA_BANK_ACCOUNT",
            "CANADA_BC_PHN",
            "CANADA_DRIVERS_LICENSE_NUMBER",
            "CANADA_OHIP",
            "CANADA_PASSPORT",
            "CANADA_QUEBEC_HIN",
            "CANADA_SOCIAL_INSURANCE_NUMBER",
            "CHILE_CDI_NUMBER",
            "CHINA_PASSPORT",
            "CHINA_RESIDENT_ID_NUMBER",
            "COLOMBIA_CDC_NUMBER",
            "CREDIT_CARD_NUMBER",
            "CREDIT_CARD_TRACK_NUMBER",
            "CROATIA_PERSONAL_ID_NUMBER",
            "DENMARK_CPR_NUMBER",
            "ENCRYPTION_KEY",
            "FINANCIAL_ACCOUNT_NUMBER",
            "FINLAND_NATIONAL_ID_NUMBER",
            "FRANCE_CNI",
            "FRANCE_NIR",
            "FRANCE_PASSPORT",
            "FRANCE_TAX_IDENTIFICATION_NUMBER",
            "GCP_API_KEY",
            "GCP_CREDENTIALS",
            "GERMANY_DRIVERS_LICENSE_NUMBER",
            "GERMANY_IDENTITY_CARD_NUMBER",
            "GERMANY_PASSPORT",
            "GERMANY_SCHUFA_ID",
            "GERMANY_TAXPAYER_IDENTIFICATION_NUMBER",
            "HONG_KONG_ID_NUMBER",
            "ICCID_NUMBER",
            "IMEI_HARDWARE_ID",
            "IMSI_ID",
            "INDIA_AADHAAR_INDIVIDUAL",
            "INDIA_GST_INDIVIDUAL",
            "INDIA_PAN_INDIVIDUAL",
            "INDIA_PASSPORT",
            "INDONESIA_NIK_NUMBER",
            "IRELAND_DRIVING_LICENSE_NUMBER",
            "IRELAND_EIRCODE",
            "IRELAND_PASSPORT",
            "IRELAND_PPSN",
            "ISRAEL_IDENTITY_CARD_NUMBER",
            "ITALY_FISCAL_CODE",
            "JAPAN_BANK_ACCOUNT",
            "JAPAN_DRIVERS_LICENSE_NUMBER",
            "JAPAN_INDIVIDUAL_NUMBER",
            "JAPAN_PASSPORT",
            "KAZAKHSTAN_PASSPORT",
            "KOREA_PASSPORT",
            "KOREA_RRN",
            "MEXICO_CURP_NUMBER",
            "MEXICO_PASSPORT",
            "NETHERLANDS_BSN_NUMBER",
            "NETHERLANDS_PASSPORT",
            "NEW_ZEALAND_IRD_NUMBER",
            "NORWAY_NI_NUMBER",
            "OAUTH_CLIENT_SECRET",
            "PARAGUAY_CIC_NUMBER",
            "PASSPORT",
            "PASSWORD",
            "PERU_DNI_NUMBER",
            "POLAND_NATIONAL_ID_NUMBER",
            "POLAND_PASSPORT",
            "POLAND_PESEL_NUMBER",
            "PORTUGAL_CDC_NUMBER",
            "PORTUGAL_SOCIAL_SECURITY_NUMBER",
            "RUSSIA_PASSPORT",
            "SCOTLAND_COMMUNITY_HEALTH_INDEX_NUMBER",
            "SINGAPORE_NATIONAL_REGISTRATION_ID_NUMBER",
            "SINGAPORE_PASSPORT",
            "SOUTH_AFRICA_ID_NUMBER",
            "SPAIN_CIF_NUMBER",
            "SPAIN_DNI_NUMBER",
            "SPAIN_DRIVERS_LICENSE_NUMBER",
            "SPAIN_NIE_NUMBER",
            "SPAIN_NIF_NUMBER",
            "SPAIN_PASSPORT",
            "SPAIN_SOCIAL_SECURITY_NUMBER",
            "SSL_CERTIFICATE",
            "STORAGE_SIGNED_POLICY_DOCUMENT",
            "STORAGE_SIGNED_URL",
            "SWEDEN_NATIONAL_ID_NUMBER",
            "SWEDEN_PASSPORT",
            "SWITZERLAND_SOCIAL_SECURITY_NUMBER",
            "TAIWAN_PASSPORT",
            "THAILAND_NATIONAL_ID_NUMBER",
            "TURKEY_ID_NUMBER",
            "UK_DRIVERS_LICENSE_NUMBER",
            "UK_ELECTORAL_ROLL_NUMBER",
            "UK_NATIONAL_HEALTH_SERVICE_NUMBER",
            "UK_NATIONAL_INSURANCE_NUMBER",
            "UK_PASSPORT",
            "UK_TAXPAYER_REFERENCE",
            "UKRAINE_PASSPORT",
            "URUGUAY_CDI_NUMBER",
            "US_ADOPTION_TAXPAYER_IDENTIFICATION_NUMBER",
            "US_DEA_NUMBER",
            "US_DRIVERS_LICENSE_NUMBER",
            "US_EMPLOYER_IDENTIFICATION_NUMBER",
            "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER",
            "US_MEDICARE_BENEFICIARY_ID_NUMBER",
            "US_PASSPORT",
            "US_PREPARER_TAXPAYER_IDENTIFICATION_NUMBER",
            "US_SOCIAL_SECURITY_NUMBER",
            "UZBEKISTAN_PASSPORT",
            "VEHICLE_IDENTIFICATION_NUMBER",
            "VENEZUELA_CDI_NUMBER",
            "WEAK_PASSWORD_HASH",
        ],
        # info_types,
        [
            "column_1",
            "column_2",
            "column_3",
            "column_4"            
        ],
    )


if __name__ == "__main__":
    main()

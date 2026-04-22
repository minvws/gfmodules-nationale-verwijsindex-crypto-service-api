import logging

import json
from pathlib import Path
from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter()

# https://www.patorjk.com/software/taag/#p=display&f=Doom&t=Skeleton
LOGO = r"""
 _   _ _   _ _____   _____                  _          _____                 _          
| \ | | | | |_   _| /  __ \                | |        /  ___|               (_)         
|  \| | | | | | |   | /  \/_ __ _   _ _ __ | |_ ___   \ `--.  ___ _ ____   ___  ___ ___ 
| . ` | | | | | |   | |   | '__| | | | '_ \| __/ _ \   `--. \/ _ \ '__\ \ / / |/ __/ _ \
| |\  \ \_/ /_| |_  | \__/\ |  | |_| | |_) | || (_) | /\__/ /  __/ |   \ V /| | (_|  __/
\_| \_/\___/ \___/   \____/_|   \__, | .__/ \__\___/  \____/ \___|_|    \_/ |_|\___\___|
                                 __/ | |                                                
                                |___/|_|                                                

NVI Crypto Service
"""


@router.get(
    "/",
    summary="API Home",
    description="Display the NVI Crypto Service welcome page with ASCII logo and version information.",
    status_code=200,
    responses={
        200: {
            "description": "API home page with logo and version info",
            "content": {
                "text/plain": {
                    "examples": {
                        "with_version": {
                            "summary": "With version info",
                            "value": LOGO + "\n\nVersion: 1.0.0\nCommit: abc123def456",
                        },
                        "no_version": {
                            "summary": "No version info",
                            "value": LOGO + "\n\nNo version information found",
                        },
                    }
                }
            },
        }
    },
    tags=["Info"],
)
def index() -> Response:
    content = LOGO

    try:
        with open(Path(__file__).parent.parent.parent / "version.json", "r") as file:
            data = json.load(file)
            content += "\nVersion: %s\nCommit: %s" % (data["version"], data["git_ref"])
    except (FileNotFoundError, json.JSONDecodeError) as e:
        content += "\nNo version information found"
        logger.debug("Version info could not be loaded: %s" % e)

    return Response(content, media_type="text/plain")


@router.get(
    "/version.json",
    summary="Get Version Info",
    description="Retrieve detailed version and build information in JSON format.",
    responses={
        200: {
            "description": "Version information retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "version": "1.0.0",
                        "git_ref": "abc123def456",
                    }
                }
            },
        },
        404: {
            "description": "Version information file not found",
            "content": {"text/plain": {"example": "Version info could not be loaded."}},
        },
    },
    tags=["Info"],
)
def version_json() -> JSONResponse:
    try:
        with open(Path(__file__).parent.parent.parent / "version.json", "r") as file:
            return JSONResponse(
                status_code=200,
                content=json.load(file),
            )
    except FileNotFoundError as e:
        logger.debug("Version info could not be loaded: %s" % e)
        return JSONResponse(
            status_code=404,
            content={"detail": "Version info could not be loaded."},
        )

    

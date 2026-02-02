import express from 'express';
import cors from 'cors';

import parse from '@yarnpkg/parsers'; 


const PORT = 3001;


const SONATYPE_API_URL = 'https://ossindex.sonatype.org/api/v3/authorized/component-report';
const SONATYPE_AUTH_TOKEN = 'Basic c2FyY2FzdGljZ2FtZXI5NkBnbWFpbC5jb206YzE2ZDM3ZWVmNjcwZDUzOGZjMTM1OWQyNTliOTM1NjgyOGQ1YWEyZg==';
const BATCH_SIZE = 1000;

// GITHUB

// *** NEW: GitHub API Config ***
// 1. Get this from GitHub > Settings > Developer settings > Tokens (classic)
// 2. Give it the "workflow" scope
const GITHUB_PAT = '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'; 
// 3. This must match the filename of the workflow in your target repo
const GITHUB_WORKFLOW_ID = 'manual-scan.yml';



const NIST_API_KEY = '3b4ecaf4-3e92-4571-a491-3905c3407ffb'; 
const NIST_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';


const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));





function parsePackageLock(content) {
  const lockfile = JSON.parse(content);
  const coordinates = new Set();
  if (lockfile.packages) {
    for (const path in lockfile.packages) {
      if (path === "" || !path.includes('node_modules/')) continue;
      const pkg = lockfile.packages[path];
      if (pkg.version) {
        const name = path.split('node_modules/').pop();
        coordinates.add(`pkg:npm/${name}@${pkg.version}`);
      }
    }
  } else if (lockfile.dependencies) {
    for (const name in lockfile.dependencies) {
      const pkg = lockfile.dependencies[name];
      coordinates.add(`pkg:npm/${name}@${pkg.version}`);
    }
  }
  return Array.from(coordinates);
}

function parseRequirements(content) {
  const coordinates = new Set();
  const lines = content.split('\n');
  for (const line of lines) {
    const trimmedLine = line.trim();
    if (trimmedLine.length === 0 || trimmedLine.startsWith('#')) continue;
    const parts = trimmedLine.split('==');
    if (parts.length === 2) {
      const name = parts[0].trim();
      const version = parts[1].trim();
      coordinates.add(`pkg:pypi/${name}@${version}`);
    }
  }
  return Array.from(coordinates);
}

function parseYarnLockV1Parser(content) {
  const json = parse(content);
  if (json.type !== 'success') {
    throw new Error('Not a v1 lockfile.');
  }
  const coordinates = new Set();
  for (const key of Object.keys(json.object)) {
    const pkg = json.object[key];
    const name = key.split('@')[0];
    coordinates.add(`pkg:npm/${name}@${pkg.version}`);
  }
  return Array.from(coordinates);
}

function parseYarnLockModernParser(content) {
    const lockfile = parse(content);
    const coordinates = new Set();
    
    for (const key in lockfile) {
        if (key === '__metadata') continue;
        const pkg = lockfile[key];
        if (pkg.version) {
            coordinates.add(`pkg:npm/${pkg.name}@${pkg.version}`);
        }
    }
    return Array.from(coordinates);
}





/**
 * Endpoint 1: Package Scanner
 * Proxies requests to the Sonatype OSS Index API
 */
app.post('/api/scan', async (req, res) => {
  const { fileName, content } = req.body;
  
  if (!fileName || !content) {
     return res.status(400).json({ error: 'Invalid request: "fileName" and "content" are required.' });
  }

  let coordinates = [];
  console.log(`Received file: ${fileName}`);

  try {
    
    if (fileName.endsWith('package-lock.json')) {
      coordinates = parsePackageLock(content);
    } else if (fileName.endsWith('requirements.txt')) {
      coordinates = parseRequirements(content);
    } else if (fileName.endsWith('yarn.lock')) {
      try {
        coordinates = parseYarnLockV1Parser(content);
        console.log('Parsed yarn.lock as v1 (Classic).');
      } catch (v1Error) {
        try {
          coordinates = parseYarnLockModernParser(content);
          console.log('Parsed yarn.lock as v2+ (Modern).');
        } catch (v2Error) {
          console.error("Failed to parse yarn.lock as v1 or v2+:", v2Error.message);
          throw new Error('Failed to parse yarn.lock. File may be corrupt or an unsupported version.');
        }
      }
    } else {
      throw new Error('Unsupported file type. Please upload package-lock.json, requirements.txt, or yarn.lock.');
    }

    if (coordinates.length === 0) {
      throw new Error('Could not parse any packages from the file. It may be empty or in an unsupported format.');
    }

    console.log(`Parsed ${coordinates.length} coordinates. Processing in batches...`);

    
    let allReports = [];
    const fetchPromises = [];

    for (let i = 0; i < coordinates.length; i += BATCH_SIZE) {
      const batch = coordinates.slice(i, i + BATCH_SIZE);
      const payload = { coordinates: batch };

      fetchPromises.push(
        fetch(SONATYPE_API_URL, {
          method: 'POST',
          headers: {
            'Accept': 'application/vnd.ossindex.component-report.v1+json',
            'Authorization': SONATYPE_AUTH_TOKEN,
            'Content-Type': 'application/vnd.ossindex.component-report-request.v1+json'
          },
          body: JSON.stringify(payload)
        })
      );
    }

    const responses = await Promise.all(fetchPromises);

    
    for (const response of responses) {
      if (!response.ok) {
        throw new Error(`Sonatype API Error: ${response.status} ${response.statusText}`);
      }
      const reports = await response.json();
      allReports.push(...reports);
    }

    console.log(`Scan complete. Found ${allReports.length} total reports.`);
    res.json(allReports);

  } catch (error) {
    console.error('Error in /api/scan:', error.message);
    res.status(500).json({ error: 'Failed to process file.', details: error.message });
  }
});

/**
 * Endpoint 2: CVE Lookup
 * Proxies requests to the NIST NVD API
 */
app.get('/api/cve', async (req, res) => {
    const { keywordSearch } = req.query;

    if (!keywordSearch) {
        return res.status(400).json({ error: 'Missing "keywordSearch" query parameter.' });
    }
    
    if (!NIST_API_KEY || NIST_API_KEY === 'YOUR_NIST_API_KEY_GOES_HERE') {
        console.error('NIST_API_KEY is not set in server.js');
        return res.status(500).json({ error: 'Server is missing NIST API key.' });
    }

    try {
        const url = `${NIST_API_URL}?keywordSearch=${encodeURIComponent(keywordSearch)}`;
        
        console.log(`Proxying CVE search for: ${keywordSearch}`);

        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'apiKey': NIST_API_KEY
            }
        });

        if (!response.ok) {
            throw new Error(`NIST API Error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        res.json(data);

    } catch (error) {
        console.error('Error in /api/cve:', error.message);
        res.status(500).json({ error: 'Failed to fetch from NIST API.', details: error.message });
    }
});


app.post('/api/trigger-workflow', async (req, res) => {
    const { repoUrl } = req.body;

    if (!repoUrl) {
        return res.status(400).json({ error: 'Missing "repoUrl"' });
    }

    if (!GITHUB_PAT) {
        console.error('GitHub PAT is not configured on the server.');
        return res.status(500).json({ error: 'Server is not configured for this action.' });
    }

    try {
        // 1. Parse the URL to get "owner" and "repo"
        const { pathname } = new URL(repoUrl);
        const [_, owner, repo] = pathname.split('/');
        
        if (!owner || !repo) {
            throw new Error('Could not parse owner and repo from URL. Use format: https://github.com/owner/repo');
        }

        const api_url = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${GITHUB_WORKFLOW_ID}/dispatches`;
        
        console.log(`Triggering workflow for: ${owner}/${repo}`);

        // 2. Make the authenticated API call to GitHub
        const response = await fetch(api_url, {
            method: 'POST',
            headers: {
                'Accept': 'application/vnd.github.v3+json',
                'Authorization': `Bearer ${GITHUB_PAT}`,
                'Content-Type': 'application/json',
                'X-GitHub-Api-Version': '2022-11-28'
            },
            body: JSON.stringify({
                ref: 'main' // This runs the workflow on the 'main' branch. Change if needed.
            })
        });

        // 3. Handle the response
        if (response.status === 204) {
            // Success (204 No Content is the correct response)
            res.status(200).json({ message: `Successfully triggered scan for ${owner}/${repo}. Check its "Actions" tab.
              
              ` });
        } else {
            // Handle errors
            const data = await response.json();
            console.error('GitHub API Error:', data.message);
            throw new Error(data.message || `GitHub API failed with status ${response.status}`);
        }

    } catch (error) {
        console.error('Error triggering workflow:', error.message);
        res.status(500).json({ error: 'Failed to trigger workflow.', details: error.message });
    }
});





app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Serving frontend from the "public" directory.');
});
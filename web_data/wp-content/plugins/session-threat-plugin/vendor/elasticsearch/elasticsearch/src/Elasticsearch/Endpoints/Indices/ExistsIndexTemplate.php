<?php
/**
 * Elasticsearch PHP client
 *
 * @link      https://github.com/elastic/elasticsearch-php/
 * @copyright Copyright (c) Elasticsearch B.V (https://www.elastic.co)
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License, Version 2.0
 * @license   https://www.gnu.org/licenses/lgpl-2.1.html GNU Lesser General Public License, Version 2.1 
 * 
 * Licensed to Elasticsearch B.V under one or more agreements.
 * Elasticsearch B.V licenses this file to you under the Apache 2.0 License or
 * the GNU Lesser General Public License, Version 2.1, at your option.
 * See the LICENSE file in the project root for more information.
 */
declare(strict_types = 1);

namespace Elasticsearch\Endpoints\Indices;

use Elasticsearch\Common\Exceptions\RuntimeException;
use Elasticsearch\Endpoints\AbstractEndpoint;

/**
 * Class ExistsIndexTemplate
 * Elasticsearch API name indices.exists_index_template
 *
 * NOTE: this file is autogenerated using util/GenerateEndpoints.php
 * and Elasticsearch 8.0.0-SNAPSHOT (ca2fb5c7ee55464068a6581480e9db6ebe569e6d)
 */
class ExistsIndexTemplate extends AbstractEndpoint
{
    protected $name;

    public function getURI(): string
    {
        $name = $this->name ?? null;

        if (isset($name)) {
            return "/_index_template/$name";
        }
        throw new RuntimeException('Missing parameter for the endpoint indices.exists_index_template');
    }

    public function getParamWhitelist(): array
    {
        return [
            'flat_settings',
            'master_timeout',
            'local'
        ];
    }

    public function getMethod(): string
    {
        return 'HEAD';
    }

    public function setName($name): ExistsIndexTemplate
    {
        if (isset($name) !== true) {
            return $this;
        }
        $this->name = $name;

        return $this;
    }
}

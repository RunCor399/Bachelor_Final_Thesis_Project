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

namespace Elasticsearch\Namespaces;

use Elasticsearch\Namespaces\AbstractNamespace;

/**
 * Class LogstashNamespace
 *
 * NOTE: this file is autogenerated using util/GenerateEndpoints.php
 * and Elasticsearch 8.0.0-SNAPSHOT (ca2fb5c7ee55464068a6581480e9db6ebe569e6d)
 */
class LogstashNamespace extends AbstractNamespace
{

    /**
     * $params['id'] = (string) The ID of the Pipeline
     *
     * @param array $params Associative array of parameters
     * @return array
     * @see https://www.elastic.co/guide/en/elasticsearch/reference/current/logstash-api-delete-pipeline.html
     */
    public function deletePipeline(array $params = [])
    {
        $id = $this->extractArgument($params, 'id');

        $endpointBuilder = $this->endpoints;
        $endpoint = $endpointBuilder('Logstash\DeletePipeline');
        $endpoint->setParams($params);
        $endpoint->setId($id);

        return $this->performRequest($endpoint);
    }
    /**
     * $params['id'] = (string) A comma-separated list of Pipeline IDs
     *
     * @param array $params Associative array of parameters
     * @return array
     * @see https://www.elastic.co/guide/en/elasticsearch/reference/current/logstash-api-get-pipeline.html
     */
    public function getPipeline(array $params = [])
    {
        $id = $this->extractArgument($params, 'id');

        $endpointBuilder = $this->endpoints;
        $endpoint = $endpointBuilder('Logstash\GetPipeline');
        $endpoint->setParams($params);
        $endpoint->setId($id);

        return $this->performRequest($endpoint);
    }
    /**
     * $params['id']   = (string) The ID of the Pipeline
     * $params['body'] = (array) The Pipeline to add or update (Required)
     *
     * @param array $params Associative array of parameters
     * @return array
     * @see https://www.elastic.co/guide/en/elasticsearch/reference/current/logstash-api-put-pipeline.html
     */
    public function putPipeline(array $params = [])
    {
        $id = $this->extractArgument($params, 'id');
        $body = $this->extractArgument($params, 'body');

        $endpointBuilder = $this->endpoints;
        $endpoint = $endpointBuilder('Logstash\PutPipeline');
        $endpoint->setParams($params);
        $endpoint->setId($id);
        $endpoint->setBody($body);

        return $this->performRequest($endpoint);
    }
}
